#include "router_hal.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

struct RouteEntry {
  u32 addr;     // big endian, e.g., 1.2.3.4 is 0x04030201 rather than 0x01020304
  u32 mask;     // big endian
  u32 nexthop;  // big endian, nexthop == 0 means direct routing
  u32 metric;   // big endian, two big endian metrics can be compared directly
  u32 if_index; // machine endian
};

std::vector<RouteEntry> table;

bool query(u32 addr, u32 *nexthop, u32 *if_index) {
  u32 max = 0;
  u32 nexthop1, if_index1;
  for (auto &e : table) {
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
  } entries[];
} __attribute__((aligned(4)));

bool check_rip(IpHdr *ip, u32 len) {
#define REQUIRE(x) \
  if (!(x))        \
    return false;

  if (BE16(ip->tot_len) > len)
    return false;
  u32 off = ip->ihl * 4 + 8;        // 8 is udp header size
  u32 count = (len - off - 4) / 20; // 4 is rip header size, 20 is entry size
  RawRip *raw = (RawRip *)((u8 *)ip + off);
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
    RawRip::Entry &e = raw->entries[i];
    u16 family = BE16(e.family);
    REQUIRE((request && family == 0) || (!request && family == 2));
    REQUIRE(e.tag == 0);
    u32 metric = BE32(e.metric);
    REQUIRE(1 <= metric && metric <= 16);
    u32 mask = BE32(e.mask);
    REQUIRE(mask == 0 || (mask | ((1 << __builtin_ctz(mask)) - 1)) == ~0u);
  }
  return true;
}

__attribute__((aligned(4))) u8 packet[2048];

// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
u32 addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};

// `iface` == -1u means send to all interfaces
void send_response(u32 iface, u32 dst_addr) {
#define SEND_ALL()                                         \
  do {                                                     \
    u32 tot_len = 20 + 8 + 4 + cnt * 20;                   \
    ip->tot_len = BE16((u16)tot_len);                      \
    ip->check = BE16(calc_check_sum(ip));                  \
    udp->len = BE16((u16)(tot_len - 20));                  \
    if (HAL_ArpGetMacAddress(i, dst_addr, dst_mac) == 0) { \
      HAL_SendIPPacket(i, packet, tot_len, dst_mac);       \
    }                                                      \
  } while (false)
  IpHdr *ip = (IpHdr *)packet;
  UdpHdr *udp = (UdpHdr *)(packet + 20);
  RawRip *rip = (RawRip *)(packet + 28);
  macaddr_t dst_mac;
  *ip = IpHdr{
      .ihl = 5,
      .version = 4,
      .tos = 0,
      .tot_len = 0, // set later
      .id = 0,
      .frag_off = 0,
      .ttl = 1,
      .protocol = 17, // udp
      .check = 0,     // set later
      .saddr = 0,     // set later
      .daddr = dst_addr,
  };
  *udp = UdpHdr{.src = BE16(520), .dst = BE16(520), .len = 0 /* set later */, .chksum = 0};
  rip->command = 2; // response
  rip->version = 2;
  rip->zero = 0;
  for (u32 i = 0; i < N_IFACE_ON_BOARD; ++i) {
    if (iface == -1u || iface == i) {
      ip->saddr = addrs[i];
      u32 cnt = 0;
      for (auto &e1 : table) {
        if (e1.nexthop == 0 || e1.if_index != i) { // split horizon
          RawRip::Entry &e2 = rip->entries[cnt];
          e2.family = BE16(2);
          e2.tag = 0;
          e2.addr = e1.addr;
          e2.mask = e1.mask;
          e2.nexthop = 0;
          e2.metric = e1.metric;
          if (++cnt == 25) {
            SEND_ALL();
            cnt = 0;
          }
        }
      }
      if (cnt != 0) {
        SEND_ALL();
      }
    }
  }
}

#define IP_FMT(x) x >> 24, x >> 16 & 0xFF, x >> 8 & 0xFF, x & 0xFF

void print_table() {
  u32 size = (u32)table.size();
  printf("table: count = %d, last 25 elements = [\n", size);
  for (u32 i = size > 25 ? size - 25 : 0; i < size; ++i) {
    RouteEntry &e = table[i];
    u32 addr = BE32(e.addr), nexthop = BE32(e.nexthop);
    printf("  { addr: %d.%d.%d.%d, mask: %x, nexthop: %d.%d.%d.%d, metric: %d, if_index: %d},\n",
           IP_FMT(addr), BE32(e.mask), IP_FMT(nexthop), BE32(e.metric), e.if_index);
  }
  printf("]\n");
}

i32 main() {
  i32 res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // Add direct routes
  for (u32 i = 0; i < N_IFACE_ON_BOARD; i++) {
    table.push_back(RouteEntry{
        .addr = addrs[i] & ((1 << 24) - 1),
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
      send_response(-1u, RIP_MULITCAST_ADDR);
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
          send_response(if_index, src_addr);
        } else { // response
          bool changed = false;
          for (u32 i = 0; i < rip_count; ++i) {
            u32 mask = rip->entries[i].mask;
            u32 addr = rip->entries[i].addr & mask;
            u32 metric = std::min(BE32(16), rip->entries[i].metric + BE32(1));
            auto it = std::find_if(table.begin(), table.end(),
                                   [addr, mask](RouteEntry &e) { return e.addr == addr && e.mask == mask; });
            if (it != table.end()) {
              if (it->nexthop == src_addr) {
                changed |= it->metric != metric;
                if ((it->metric = metric) == BE32(16)) {
                  std::swap(*it, table.back());
                  table.pop_back();
                }
              } else if (it->metric > metric) {
                changed = true;
                it->nexthop = src_addr;
                it->metric = metric;
                it->if_index = if_index;
              }
            } else {
              changed = true;
              table.push_back(RouteEntry{addr, mask, src_addr, metric, if_index});
            }
          }
          if (changed) {
            printf("changed, src_addr = %d.%d.%d.%d\n", IP_FMT(BE32(src_addr)));
            print_table();
          }
        }
      }
    } else { // forward
      u32 nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          if (ip->ttl == 0) {
            // todo: send icmp tle
          } else {
            // naive checksum
            // --ip->ttl;
            // ip->check = BE16(calc_check_sum(ip));
            // incremental checksum
            u16 old = BE16(ip->check);
            --ip->ttl;
            u32 sum = old + 0x100;
            sum = (sum & 0xFFFF) + (sum >> 16);
            ip->check = BE16((u16)(sum == 0xFFFF ? 0 : sum));
            HAL_SendIPPacket(dest_if, packet, res, dest_mac);
          }
        } else {
          // not found, you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found, optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", dst_addr);
      }
    }
  }
  return 0;
}
