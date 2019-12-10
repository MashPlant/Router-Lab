#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <vector>

#include "router.h"

typedef struct {
  uint32_t addr;
  uint32_t mask;
  uint32_t if_index;
  uint32_t nexthop;
} Entry;

std::vector<Entry> table;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 */
void update(bool insert, RoutingTableEntry entry) {
  uint32_t addr = entry.addr, mask = (1ULL << entry.len) - 1;
  auto pos = std::find_if(table.begin(), table.end(), [addr, mask](const Entry &e) { return e.addr == addr && e.mask == mask; });
  if (insert) {
    if (pos != table.end()) {
      pos->if_index = entry.if_index;
      pos->nexthop = entry.nexthop;
    } else {
      table.push_back(Entry{addr, mask, entry.if_index, entry.nexthop});
    }
  } else if (pos != table.end()) {
    std::swap(*pos, table.back());
    table.pop_back();
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  uint32_t max = 0;
  uint32_t nexthop1, if_index1;
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