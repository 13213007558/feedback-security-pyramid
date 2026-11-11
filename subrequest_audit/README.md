# `invoke_subrequest` 与 tween 鉴权：验证与加固

验证环境：Pyramid 2.2.dev0（本仓库 `src/pyramid`，editable 安装于 `.venv`）。

## 结论先行

团队的判断 **不成立**。`Request.invoke_subrequest(subreq)` 的
`use_tweens` 参数默认是 `False`，子请求直接进入 Router 的主处理器
`orig_handle_request`，**整条 tween 链（包括写在 tween 里的鉴权）都不会执行**。
因此“鉴权写在 tween 里，内部视图一定被同一检查保护”在默认调用方式下是错的。

## 框架承诺 vs 应用自己的检查

| 行为 | 谁提供 | `use_tweens=False`（默认） | `use_tweens=True` |
|---|---|---|---|
| tween 链执行（含 tween 鉴权、`excview`、`pyramid_tm` 等） | 应用/扩展装配 | 跳过 | 执行 |
| 视图 `permission=` 的授权检查（安全策略 `permits`） | 框架，在主处理器 `_call_view(secure=True)` 内 | **仍然执行** | 仍然执行 |
| threadlocal 压栈/出栈，`get_current_request()` 返回子请求并在返回后恢复外层 | 框架，`Router.invoke_subrequest` + `RequestContext` | 保证 | 保证 |
| `NewRequest`/`ContextFound`/`NewResponse`、response/finished 回调 | 框架 | 执行 | 执行 |
| 子请求携带谁的凭据 | **应用责任**：`Request.blank` 不复制外层头，身份是子请求自己的 | — | — |
| 异常视图（exception view） | 框架，但由 `excview_tween` 调用 | 跳过：异常直接抛给调用方 | 执行：异常转成 Response |

关键区分：框架只承诺“**配了 `permission=` 的视图，授权检查绕不过去**”和
“**threadlocal 会正确恢复**”；它**不承诺**“子请求会经过你写的 tween”，
也**不承诺**子请求继承外层身份。把鉴权只放在 tween 里，等于把安全边界建在
一个可被一行参数绕过的位置。

## 源码证据

- `src/pyramid/router.py`：`Router.__init__` 把 `handle_request` 用 tween 包装，
  原始处理器存为 `orig_handle_request`；`invoke_subrequest(..., use_tweens=False)`
  在 `invoke_request` 中走 `orig_handle_request`。
- `src/pyramid/router.py` `invoke_subrequest`：`with RequestContext(request)`
  管理 threadlocal，`__exit__` 必定 `manager.pop()`，所以外层请求必然恢复。
- `src/pyramid/view.py` `_call_view(..., secure=True)`：secured view 包装器
  （`viewderivers.py` 的 `secured_view`）调用安全策略 `permits`，拒绝则抛
  `HTTPForbidden`。这一步在主处理器内，与 tween 无关。
- `src/pyramid/tweens.py`：异常视图由 `excview_tween_factory` 调用，属于 tween 链；
  默认 tween 顺序里自定义 tween 排在 `excview` 之外（更靠近 ingress）。
- `docs/narr/subrequest.rst`：官方文档明确写出默认跳过 tween、异常会直接抛出、
  以及“授权检查无条件执行”。

## 实测证据（运行方式见下）

最小应用 `app.py` 包含一个只靠 tween 保护的内部视图 `/internal/loose`
（无 `permission=`）和一个带 `permission='admin'` 的 `/internal/protected`，
外层请求带 `X-User: admin`，子请求用匿名的新 `Request.blank`。

1. **默认子请求绕过 tween**：`GET /public/loose`（外层 admin）→ 子请求到达
   `/internal/loose`，审计日志里该路径没有任何 tween 事件，视图看到的身份是
   `null`。直接匿名请求同一路径则被 tween 返回 403 —— 同一检查，两种结果。
2. **`use_tweens=True`**：tween 收到的是**子请求对象本身**（审计日志中
   path=/internal/loose、identity=None），并由 tween 拒绝；外层请求在返回后恢复。
3. **权限检查不依赖 tween**：`/public/protected` 即使 `use_tweens=False`，
   子请求仍被安全策略拒绝（`failed permission check`），受保护视图函数未执行；
   子请求显式带上自己的 admin 头时才放行，视图看到的身份是 `admin`。
4. **子请求异常**：`use_tweens=False` 时 `ValueError` 直接抛回外层视图，
   异常视图不执行；`use_tweens=True` 且凭据通过 tween 后，`excview` 把异常
   渲染成 500 响应。注意自定义鉴权 tween 默认在 `excview` 外侧，它自己抛/返回
   的 403 不会经过 forbidden/exception view。
5. **嵌套子请求**：子请求再发子请求，两层都跳过 tween，每层
   `get_current_request()` 都正确指向当前层，返回外层后逐帧恢复。
6. **请求恢复**：所有场景外层视图均断言
   `id(get_current_request()) == id(request)`（含异常路径），全部成立。

## 封死绕过路径的接法

见 `hardened.py`，四条规则：

1. 授权挂在视图上：`add_view(..., permission='admin')` + `set_security_policy(...)`。
   该检查在主处理器内，子请求无论如何都绕不过。
2. tween 只做日志、限流等横切关注点；即使保留 tween 鉴权也只是纵深防御，
   不是唯一边界。
3. 子请求一律新建 `Request.blank`，**显式**传播需要的凭据（统一收口在
   `call_internal`），不依赖外层身份的隐式继承。
4. 调用方对结果做防御性复查（捕获 `HTTPForbidden`、再断言一次所需权限），
   不把“内部调用”当作可信等级。

## 运行

```bash
.venv/bin/python -m subrequest_audit.verify     # 打印全部场景 + 审计轨迹 + 22 项断言
.venv/bin/python -m pytest subrequest_audit -q  # 14 项回归测试
```
