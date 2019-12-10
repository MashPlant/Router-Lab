// #include "../..//HAL/include/router_hal.h"
#include "router_hal.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i32 = int32_t;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BE16(x) __builtin_bswap16(x)
#define BE32(x) __builtin_bswap32(x)
#else
#define BE16(x) x
#define BE32(x) x
#endif

const u32 RIP_MULITCAST_ADDR = 0x090000e0;

struct IpHdr {
  u8 ihl : 4, version : 4;
  u8 tos;
  u16 tot_len;
  u16 id;
  u16 frag_off;
  u8 ttl;
  u8 protocol;
  u16 check;
  u32 saddr;
  u32 daddr;
} __attribute__((aligned(4)));

struct UdpHdr {
  u16 src;
  u16 dst;
  u16 len;
  u16 chksum;
} __attribute__((aligned(4)));

struct IcmpPkt {
  u8 type;
  u8 code;
  u16 chksum;
  u16 unused;
  u8 remain[0];
  // IP header and first 8 bytes of original datagram's data
};

u16 calc_check_sum(IpHdr *ip) {
  u16 old = ip->check;
  ip->check = 0;
  u32 sum = 0;
  for (u16 *p = (u16 *)ip, *end = p + ip->ihl * 2; p < end; ++p) {
    sum += BE16(*p);
  }
  ip->check = old;
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  return (u16)~sum;
}

// 约定 addr 和 nexthop 以 **大端序** 存储。
// 这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
// 保证 addr 仅最低 len 位可能出现非零。
// 当 nexthop 为零时这是一条直连路由。
struct RouteEntry {
  u32 addr;     // 大端序，IPv4 地址
  u32 mask;     // (1ULL << len) - 1, bigger is better match
  u32 nexthop;  // 大端序，下一跳的 IPv4 地址
  u32 metric;   // 大端序(两个大端序的metric可以直接比较大小)
  u32 if_index; // 小端序，出端口编号
};

std::vector<RouteEntry> table;

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(u32 addr, u32 *nexthop, u32 *if_index) {
  u32 max = 0;
  u32 nexthop1, if_index1;
  for (const auto &e : table) {
    if (e.mask > max && (addr & e.mask) == e.addr) {
      max = e.mask;
      nexthop1 = e.nexthop;
      if_index1 = e.if_index;
    }
  }
  if (max != 0) {
    *nexthop = nexthop1;
    *if_index = if_index1;
  }
  return max;
}

struct RawRip {
  u8 command; // 1(request) or 2(reponse)
  u8 version; // 2
  u16 zero;
  struct Entry {
    u16 family; // 0(request) or 2(response)
    u16 tag;    // 0
    u32 addr;
    u32 mask;
    u32 nexthop;
    u32 metric; // [1, 16]
  } entries[0];
} __attribute__((aligned(4)));

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回
 * true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len
 * 时，把传入的 IP 包视为不合法。 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool check_rip(const IpHdr *ip, u32 len) {
#define REQUIRE(x) \
  if (!(x))        \
    return false;

  if (BE16(ip->tot_len) > len)
    return false;
  u32 off = ip->ihl * 4 + 8;        // 8 is udp header size
  u32 count = (len - off - 4) / 20; // 4 is rip header size, 20 is entry size
  const RawRip *raw = (const RawRip *)((u8 *)ip + off);
  bool request;
  if (raw->command == 1) {
    request = true;
  } else if (raw->command == 2) {
    request = false;
  } else {
    return false;
  }
  REQUIRE(raw->version == 2);
  REQUIRE(raw->zero == 0);
  for (u32 i = 0; i < count; ++i) {
    const RawRip::Entry *src = &raw->entries[i];
    u16 family = BE16(src->family);
    REQUIRE((request && family == 0) || (!request && family == 2));
    REQUIRE(src->tag == 0);
    u32 metric = BE32(src->metric);
    REQUIRE(1 <= metric && metric <= 16);
    u32 mask = BE32(src->mask);
    REQUIRE(mask == 0 || (mask | ((1 << __builtin_ctz(mask)) - 1)) == ~0u);
  }
  return true;
}

__attribute__((aligned(4))) u8 packet[2048];

// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
u32 addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};
macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};

// `iface` == -1u means send to all interfaces
void send_response(u32 iface) {
  IpHdr *ip = (IpHdr *)packet;
  UdpHdr *udp = (UdpHdr *)(packet + 20);
  RawRip *rip = (RawRip *)(packet + 28);
  *ip = IpHdr{
      .ihl = 5,
      .version = 4,
      .tos = 0xc0,  // 110 0000 0, 110 = Internetwork Control
      .tot_len = 0, // set later
      .id = 0,
      .frag_off = 0,
      .ttl = 1,
      .protocol = 17, // udp
      .check = 0,     // set later
      .saddr = 0,     // set later
      .daddr = RIP_MULITCAST_ADDR,
  };
  *udp = UdpHdr{.src = BE16(520), .dst = BE16(520), .len = 0 /* set later */, .chksum = 0};
  rip->command = 2; // response
  rip->version = 2;
  rip->zero = 0;
  for (u32 i = 0; i < N_IFACE_ON_BOARD; ++i) {
    if (iface == -1u || iface == i) {
      u32 cnt = 0;
      for (auto &e1 : table) {
        if (e1.nexthop != addrs[i]) { // split horizon
          RawRip::Entry &e2 = rip->entries[cnt];
          e2.family = BE16(2);
          e2.tag = 0;
          e2.addr = e1.addr;
          e2.mask = e1.mask;
          e2.nexthop = 0;
          e2.metric = e1.metric;
          if (++cnt == 25) {
            break;
          }
        }
      }
      u32 tot_len = 20 + 8 + 4 + cnt * 20;
      ip->tot_len = BE16((u16)tot_len);
      ip->saddr = addrs[i];
      ip->check = BE16(calc_check_sum(ip));
      udp->len = BE16((u16)(tot_len - 20));
      HAL_SendIPPacket(i, packet, tot_len, multicast_mac);
    }
  }
}

i32 main() {
  i32 res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // Add direct routes
  for (u32 i = 0; i < N_IFACE_ON_BOARD; i++) {
    table.push_back(RouteEntry{
        .addr = addrs[i],
        .mask = (1 << 24) - 1,
        .nexthop = 0,
        .metric = BE32(1),
        .if_index = i,
    });
  }

  { // initially send RIP Request to all interfaces
    IpHdr *ip = (IpHdr *)packet;
    UdpHdr *udp = (UdpHdr *)(packet + 20);
    RawRip *rip = (RawRip *)(packet + 28);
    u32 tot_len = 20 + 8 + 4 + 20; // 1 entry
    *ip = IpHdr{
        .ihl = 5,
        .version = 4,
        .tos = 0,
        .tot_len = BE16((u16)tot_len),
        .id = 0,
        .frag_off = 0,
        .ttl = 1,
        .protocol = 17, // udp
        .check = 0,     // set later
        .saddr = 0,     // set later
        .daddr = RIP_MULITCAST_ADDR,
    };
    *udp = UdpHdr{.src = BE16(520), .dst = BE16(520), .len = BE16((u16)(tot_len - 20)), .chksum = 0};
    rip->command = 1; // request
    rip->version = 2;
    rip->zero = 0;
    rip->entries[0] = RawRip::Entry{
        .family = 0,
        .tag = 0,
        .addr = 0, // addr, mask nexthtop not used in a request
        .mask = 0,
        .nexthop = 0,
        .metric = BE32(16), // infinity
    };
    for (u32 i = 0; i < N_IFACE_ON_BOARD; ++i) {
      ip->saddr = addrs[i];
      ip->check = BE16(calc_check_sum(ip));
      HAL_SendIPPacket(i, packet, tot_len, multicast_mac);
    }
  }

  u64 last_time = 0;
  while (1) {
    u64 time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      printf("5s Timer\n");
      last_time = time;
      send_response(-1u);
    }
    macaddr_t src_mac;
    macaddr_t dst_mac;
    u32 if_index;
    res = HAL_ReceiveIPPacket((1 << N_IFACE_ON_BOARD) - 1, packet, sizeof(packet), src_mac, dst_mac, 1000, (i32 *)&if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > (i32)sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }
    IpHdr *ip = (IpHdr *)packet;

    if (calc_check_sum(ip) != BE16(ip->check)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    u32 src_addr = ip->saddr, dst_addr = ip->daddr;

    // assume N_IFACE_ON_BOARD == 4
    bool dst_is_me = dst_addr == RIP_MULITCAST_ADDR || dst_addr == addrs[0] || dst_addr == addrs[1] || dst_addr == addrs[2] || dst_addr == addrs[3];

    if (dst_is_me) {
      if (check_rip(ip, res)) {
        u32 off = ip->ihl * 4 + 8;            // 8 is udp header size
        u32 rip_count = (res - off - 4) / 20; // 4 is rip header size, 20 is entry size
        RawRip *rip = (RawRip *)(packet + off);
        if (rip->command == 1) { // request
          send_response(if_index);
        } else { // response
          for (u32 i = 0; i < rip_count; ++i) {
            u32 addr = rip->entries[i].addr, mask = rip->entries[i].mask;
            u32 metric = std::min(BE32(16), rip->entries[i].metric + BE32(1));
            auto it = std::find_if(table.begin(), table.end(), [addr, mask](const RouteEntry &e) { return e.addr == addr && e.mask == mask; });
            if (it != table.end()) {
              if (it->nexthop == src_addr) {
                if ((it->metric = metric) == BE32(16)) {
                  std::swap(*it, table.back());
                  table.pop_back();
                }
              } else if (it->metric > metric) {
                it->nexthop = rip->entries[i].nexthop;
                it->metric = metric;
                it->if_index = if_index;
              }
            } else {
              table.push_back(RouteEntry{addr, mask, src_addr, metric, if_index});
            }
          }
          // todo: triggered updates? ref. RFC2453 3.10.1
        }
      }
    } else {
      // forward
      // beware of endianness
      u32 nexthop, dest_if;
      if (query(src_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          if (ip->ttl == 0) {
            // todo: send icmp tle
          } else {
            --ip->ttl;
            ip->check = BE16(calc_check_sum(ip));
            HAL_SendIPPacket(dest_if, packet, res, dest_mac);
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
