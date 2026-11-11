# 用 `principals_allowed_by_permission` 构建安全搜索索引的设计说明

> 结论先行：**不能**把 `principals_allowed_by_permission`（下称 pabp）的结果直接当作
> 资源的"可访问用户列表"来做最终授权；**可以**把它存成"可访问 principal 集合"，
> 作为搜索索引的**粗筛（候选集生成器）**，但读取结果时必须再用 `permits` 逐条验证。
> 本文所有结论均可由 `pabp_index_demo.py` 复现（基于本仓库 `src/pyramid/authorization.py`
> 的 `ACLHelper` 实现，未改动任何 ACL 语义）。

## 1. 两者的语义差异（实现层面）

`ACLHelper.permits`（src/pyramid/authorization.py:96）：
- 沿 lineage **从 context 向 root** 走，逐条 ACE **按序**匹配；
- 匹配条件是"ACE 的 principal ∈ 该用户的**全部** effective principals"；
- **首个命中的 ACE 直接决定** Allow/Deny，立即返回；
- 因此它是**逐用户**的判定：同一个用户的任意一个 principal 被 Deny 命中，
  就会压过更远处对另一个 principal 的 Allow。

`ACLHelper.principals_allowed_by_permission`（src/pyramid/authorization.py:154）：
- 沿 lineage **从 root 向 context** 走，累积一个 **principal 集合**；
- 每层独立算 `allowed_here` / `denied_here`；`(Deny, P, perm)` 只把 **P 自己**
  从已累积集合中移除（`(Deny, Everyone, ...)` 会清空整个集合并 `break`）；
- 它回答的是"**哪些 principal** 被显式允许"，而不是"**哪个用户**被允许"。

关键错位：Deny 的作用是**逐 principal** 的，而用户能否访问取决于其
**principal 集合的任一成员是否被近处 Deny 命中**。把 pabp 集合与用户 principals
做交集（`index_set ∩ user_principals ≠ ∅`）时，"用户的一个 principal 被 Deny"
无法传播到"该用户的其他 principal"，于是产生**假阳性**。

## 2. 最小反例（demo 第 1、2 节实测）

**反例 A：子资源 Deny 具体用户 + 父资源 Allow Everyone**

```python
root.__acl__   = [(Allow, Everyone, 'view')]
leaked.__acl__ = [(Deny, 'user:bob', 'view')]   # leaked 是 root 的子孙
```

- `pabp(leaked, 'view')` = `{system.Everyone}`（Deny 只移除 `user:bob`，
  而 `user:bob` 根本不在集合里，`Everyone` 保留）；
- bob 的 principals 含 `Everyone` → 交集非空 → 索引判定**可见**；
- `permits(leaked, bob的principals, 'view')` → **ACLDenied**（子级 Deny 先命中）。

**反例 B：用户同时属于多个组 + 同一 ACL 内 Deny 在前**

```python
staff.__acl__ = [(Deny, 'group:interns', 'view'),
                 (Allow, 'group:staff', 'view')]
# carol 同时属于 group:staff 和 group:interns
```

- `pabp` = `{group:staff, system.Everyone}` → carol 交集非空 → 索引判定**可见**；
- `permits` 按序首个命中的是 `(Deny, group:interns, ...)` → **ACLDenied**。

**对比：哪些情况是一致的**（demo 中实测全部一致）：
- `DENY_ALL`（即 `(Deny, Everyone, ALL_PERMISSIONS)`）之下子资源重新
  `(Allow, 'user:alice', 'view')`：两者都允许 alice、都拒绝其他人。
  因为 Deny Everyone 对**所有用户的所有 principal** 一视同仁，
  "逐 principal"与"逐用户"在此重合；
- 纯 Allow（无任何 Deny）的 ACL 体系；
- `ALL_PERMISSIONS`：通过 `AllPermissionsList.__contains__` 恒真
  （src/pyramid/security.py:404），pabp 与 permits 都能正确匹配，不构成差异来源。

## 3. 直接当"可访问用户列表"不成立的三个独立原因

1. **粒度错误（反例 A/B）**：交集语义在存在"具体 principal 的 Deny"时产生假阳性。
2. **返回的是 principal 不是用户**（demo 第 3 节）：集合里是
   `system.Everyone`、`system.Authenticated`、`group:*`、`user:*` 的混合。
   `Everyone`/`Authenticated` 根本无法展开成用户名单；把 `group:*` 在建索引时
   展开成用户，则**组成员变更必须重建索引**。
3. **动态 `__acl__` 是快照**（demo 第 4 节）：`__acl__` 为 property/可调用对象时，
   pabp 在建索引那一刻求值一次；状态翻转（如资源被锁定为 `DENY_ALL`）后，
   索引立即过期，而 `permits` 永远反映当前值。

## 4. 成立条件（何时交集语义与 permits 完全等价）

充分条件（满足其一即可让"索引 ∩ 用户 principals"与 `permits` 逐点等价）：

- 全部 ACL 中**只出现 Allow 与 `(Deny, Everyone, ...)`（DENY_ALL 式）**，
  不出现对具体用户/组/`Authenticated` 的 Deny；或
- 更一般地：不存在这样的 principal P——P 在某层被 Deny，而 P 与另一个在
  更外层（或同层更后）被 Allow 的 principal **可能同属于一个用户**。

一旦业务需要"在父资源开放、在子资源拉黑某人/某组"（这正是 ACL 继承的常见用法），
等价性即被破坏，索引只能当粗筛。

## 5. 为什么仍能当粗筛：无假阴性（demo 第 5 节实测为 0）

**命题**：在索引新鲜的前提下，`permits(context, S, perm)` 允许 ⇒
`pabp(context, perm) ∩ S ≠ ∅`。

**直觉证明**：`permits` 允许 ⇒ 沿 context→root 首个命中的 ACE 是某层 L 的
`(Allow, P, perm)` 且 P ∈ S。那么 L 的内层（更靠近 context）不存在命中 P 或
Everyone 的 Deny（否则它会先命中并拒绝）；同层 L 内 P 之前也没有 Deny P。
而 pabp 从集合中移除 P 的唯一途径是"内层 Deny P"或"内层 Deny Everyone"——
两者均不存在，故 P 必留在结果集合中，交集非空。∎

即索引**只会多报、不会漏报**，这正好是搜索预筛选需要的方向。

## 6. 落地设计

**索引可以承担的工作**
- 按 `(resource, permission)` 存 pabp 返回的 **principal 集合**（原样存，
  不要展开成用户）；查询时用当前用户的全部 effective principals 求交，
  交集为空 ⇒ 安全地**直接排除**（无需查库/无需 permits）；
- 大幅缩小候选集，把 O(全库) 的权限过滤降到 O(候选集)；
- `Everyone`/`Authenticated` 作为普通集合元素参与交集即可，天然支持匿名访问。

**读取结果时必须验证的**
- 对交集非空的**每一条候选**，在返回/渲染前调用
  `permits(context, 当前用户的effective principals, permission)` 做最终判定
  （或等价的 `request.has_permission`）。候选数量小，代价可控；
- 任何"列表页直接展示敏感字段"的场景，同样只能展示通过 permits 的条目。

**索引的失效与重建条件**
- 任何资源的 `__acl__` 被修改（含动态 `__acl__` 依赖的状态变化）→
  重建该资源**及其整棵子树**的索引条目（Deny/Allow 的影响沿 lineage 传播）；
- 资源在树中移动（`__parent__` 变化）→ 同上；
- **组成员变更不需要重建**（因为索引存的是 principal 而非用户）——
  这是"存 principal 集合"相对"存用户列表"的最大工程收益；
- 动态 `__acl__` 依赖外部状态（时间、锁标志等）时，要么订阅该状态的变更事件
  触发重建，要么对这些资源放弃索引、查询时直走 permits。

**按 permission 分别建索引**：pabp 是针对单个 permission 求的；
`ALL_PERMISSIONS` 的 ACE 会被包含进每个 permission 的集合，无需特殊处理，
但不同 permission 的集合必须分开存。

## 7. 复现

```bash
cd security-index-demo
python3 pabp_index_demo.py
```

输出分 5 节：逐资源×逐用户的对照表、假阳性明细、pabp 返回值形态、
动态 `__acl__` 快照过期演示、假阴性计数（=0）。
