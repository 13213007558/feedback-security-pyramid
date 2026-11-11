"""
对比实验：principals_allowed_by_permission 的集合语义 vs permits 的逐用户判定。

运行：python3 pabp_index_demo.py
"""
from pyramid.authorization import (
    ACLAuthorizationPolicy,
    ALL_PERMISSIONS,
    DENY_ALL,
    Allow,
    Authenticated,
    Deny,
    Everyone,
)

policy = ACLAuthorizationPolicy()


class Node:
    def __init__(self, name, parent=None, acl=None):
        self.__name__ = name
        self.__parent__ = parent
        if acl is not None:
            self.__acl__ = acl
        self.children = {}

    def add(self, name, acl=None):
        child = Node(name, parent=self, acl=acl)
        self.children[name] = child
        return child


# ---------------------------------------------------------------- 资源树
# root: 所有人可 view，editors 组可 edit（含 ALL_PERMISSIONS 的 admin）
root = Node('root', acl=[
    (Allow, Everyone, 'view'),
    (Allow, 'group:editors', 'edit'),
    (Allow, 'user:admin', ALL_PERMISSIONS),
])

# 场景 A：子资源 Deny 具体用户，父资源 Allow Everyone
public = root.add('public')                      # 无 ACL，继承 root
leaked = public.add('leaked', acl=[
    (Deny, 'user:bob', 'view'),
])

# 场景 B：同一 ACL 内 Deny 在前、Allow 在后；用户同时属于两个组
staff = root.add('staff', acl=[
    (Deny, 'group:interns', 'view'),
    (Allow, 'group:staff', 'view'),
])
handbook = staff.add('handbook')                 # 无 ACL，继承 staff

# 场景 C：DENY_ALL 之下子资源重新 Allow（应当一致的分支）
vault = root.add('vault', acl=[DENY_ALL])
gem = vault.add('gem', acl=[
    (Allow, 'user:alice', 'view'),
])

# 场景 D：动态 __acl__（property，依赖可变状态）
class DynamicNode(Node):
    def __init__(self, name, parent):
        super().__init__(name, parent=parent)
        self.locked = False

    @property
    def __acl__(self):
        if self.locked:
            return [DENY_ALL]
        return [(Allow, 'group:staff', 'view')]

ticket = DynamicNode('ticket', parent=root)
root.children['ticket'] = ticket

# ---------------------------------------------------------------- 用户
USERS = {
    'anon':  [Everyone],
    'alice': [Everyone, Authenticated, 'user:alice', 'group:editors'],
    'bob':   [Everyone, Authenticated, 'user:bob', 'group:staff'],
    'carol': [Everyone, Authenticated, 'user:carol',
              'group:staff', 'group:interns'],   # 同时属于两个组
}

RESOURCES = [root, public, leaked, staff, handbook, vault, gem, ticket]


def path(node):
    parts = []
    while node is not None:
        parts.append(node.__name__)
        node = node.__parent__
    return '/' + '/'.join(reversed(parts))


def index_visible(node, principals, permission):
    """模拟安全搜索索引：资源上存 pabp 集合，查询时与用户 principal 求交。"""
    allowed = policy.principals_allowed_by_permission(node, permission)
    return bool(set(principals) & allowed), allowed


print('=== 1. pabp 集合 ∩ 用户 principals  vs  permits 实际判定 (permission=view) ===')
print(f'{"resource":<22}{"user":<7}{"index":<7}{"permits":<9}结论')
divergences = []
for res in RESOURCES:
    for user, principals in USERS.items():
        visible, allowed = index_visible(res, principals, 'view')
        actual = bool(policy.permits(res, principals, 'view'))
        if visible != actual:
            divergences.append((res, user, visible, actual, allowed))
        mark = '' if visible == actual else '  <-- 不一致'
        print(f'{path(res):<22}{user:<7}{str(visible):<7}{str(actual):<9}{mark}')

print()
print('=== 2. 不一致明细（假阳性：索引可见但 permits 拒绝）===')
for res, user, visible, actual, allowed in divergences:
    print(f'{path(res)} user={user}: index={visible} permits={actual}')
    print(f'    pabp 集合 = {sorted(allowed)}')

print()
print('=== 3. pabp 返回的是 principal 而不是用户 ===')
print('root 的 pabp(view) =',
      sorted(policy.principals_allowed_by_permission(root, 'view')))
print('root 的 pabp(edit) =',
      sorted(policy.principals_allowed_by_permission(root, 'edit')))

print()
print('=== 4. 动态 __acl__：索引是快照，permits 是实时 ===')
ticket.locked = False
snapshot = policy.principals_allowed_by_permission(ticket, 'view')  # 索引时刻
ticket.locked = True                                                # 之后资源被锁定
print(f'索引快照 pabp = {sorted(snapshot)}')
for user, principals in USERS.items():
    idx = bool(set(principals) & snapshot)
    actual = bool(policy.permits(ticket, principals, 'view'))
    if idx != actual:
        print(f'  user={user}: 索引(快照)={idx} 但 permits(当前)={actual}  <-- 索引过期')

print()
print('=== 5. 反向安全性：索引交集为空 => permits 必然拒绝？===')
false_negatives = 0
for res in RESOURCES:
    for user, principals in USERS.items():
        visible, _ = index_visible(res, principals, 'view')
        actual = bool(policy.permits(res, principals, 'view'))
        if not visible and actual:
            false_negatives += 1
            print(f'  假阴性: {path(res)} user={user}')
print(f'假阴性数量 = {false_negatives}（0 表示索引可作"候选集"粗筛）')
