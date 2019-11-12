#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

u16 overflowing_add(u16 a, u16 b) {
  u32 x = (u32)a + b;
  x = (x & 0xFFFF) + (x >> 16);
  return (u16)x;
}

// will override the old check sum
u16 calc_check_sum(u8 *packet) {
  iphdr *hdr = (iphdr *)packet;
  hdr->check = 0;
  u16 sum = 0;
  for (u16 *p = (u16 *)packet, *end = p + hdr->ihl * 2; p < end; ++p) {
    sum = overflowing_add(sum, BE16(*p));
  }
  return ~sum;
}

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t _len) {
  u16 old = BE16(((iphdr *)packet)->check);
  return calc_check_sum(packet) == old;
}