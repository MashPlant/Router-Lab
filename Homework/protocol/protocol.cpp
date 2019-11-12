#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rip.h"

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BE16(x) __builtin_bswap16(x)
#define BE32(x) __builtin_bswap32(x)
#else
#define BE16(x) x
#define BE32(x) x
#endif

struct iphdr {
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
};

struct RawRip {
  u8 command;  // 1(request) or 2(reponse)
  u8 version;  // 2
  u16 zero;
  struct Entry {
    u16 family;  // 0(request) or 2(response)
    u16 tag;     // 0
    u32 addr;
    u32 mask;  // todo
    u32 nexthop;
    u32 metric;  // [1, 16]
  } entries[0];
};

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
#define REQUIRE(x) \
  if (!(x)) return false;

  iphdr *hdr = (iphdr *)packet;
  if (BE16(hdr->tot_len) > len) return false;
  u32 off = hdr->ihl * 4 + 8;        // 8 is udp header size
  u32 count = (len - off - 4) / 20;  // 4 is rip header size, 20 is entry size
  const RawRip *raw = (const RawRip *)(packet + off);
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
  output->numEntries = count;
  output->command = raw->command;
  for (u32 i = 0; i < count; ++i) {
    const RawRip::Entry *src = &raw->entries[i];
    u16 family = BE16(src->family);
    REQUIRE((request && family == 0) || (!request && family == 2));
    REQUIRE(src->tag == 0);
    u32 metric = BE32(src->metric);
    REQUIRE(1 <= metric && metric <= 16);
    u32 mask = BE32(src->mask);
    REQUIRE(mask == 0 || (mask | ((1 << __builtin_ctz(mask)) - 1)) == ~0);
    memcpy(&output->entries[i].addr, &src->addr, 4 * sizeof(u32));
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  RawRip *raw = (RawRip *)buffer;
  u32 count = rip->numEntries;
  raw->command = rip->command;
  raw->version = 2;
  raw->zero = 0;
  u16 family = rip->command == 1 ? 0 : BE16(2);
  for (u32 i = 0; i < count; ++i) {
    RawRip::Entry *dst = &raw->entries[i];
    dst->family = family;
    dst->tag = 0;
    memcpy(&dst->addr, &rip->entries[i], 4 * sizeof(u32));
  }
  return 4 + 20 * count;
}
