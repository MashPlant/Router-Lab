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

u16 calc_check_sum(u8 *packet) {
  iphdr *hdr = (iphdr *)packet;
  u16 old = hdr->check;
  hdr->check = 0;
  u32 sum = 0;
  for (u16 *p = (u16 *)packet, *end = p + hdr->ihl * 2; p < end; ++p) {
    sum += BE16(*p);
  }
  hdr->check = old;
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // 在这里你不需要考虑 TTL 为 0 的情况，在最终你的路由器实现中才做要求
  u16 old = BE16(((iphdr *)packet)->check);
  if (calc_check_sum(packet) != old) {
    return false;
  }
  iphdr *hdr = (iphdr *)packet;
  --hdr->ttl;
  u32 sum = old + 0x100;
  sum = (sum & 0xFFFF) + (sum >> 16);
  hdr->check = BE16((u16) (sum == 0xFFFF ? 0 : sum));
  return true;
}