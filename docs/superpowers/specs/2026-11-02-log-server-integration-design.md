# NetPulse 远程日志上报接入设计

- 日期：2026-11-02
- 版本：v1.17.0（未发布）
- 状态：已确认，待实现

## 1. 动机

程序主要跑在客户机器上。此前崩溃只写本地 `reports/netpulse_error.log`，厂商拿不到现场栈，
只能等用户截图回传，复现率极低（v1.16.1 的提权重启崩溃就是这样才暴露出来的）。

本次把客户端运行期的**软件自身问题**推送到统一日志服务器，让优化闭环不依赖用户配合。

## 2. 服务端接口

```bash
curl -X POST https://router.silentcrow.top:9800/v1/logs \
  -H "Content-Type: application/json" \
  -H "X-Token: app-tk_87a4d0bc31508c1f0b10dd8eb116f165" \
  -d '{"app":"netpulse","type":"error","message":"...","stack":"...","ts":"...","os":"..."}'
```

### 2.0 TLS 与证书 pin

服务端是**自签证书**：

| 项 | 值 |
|---|---|
| Subject / Issuer | `CN=logserver`（自签） |
| BasicConstraints | `CA=True`（可作信任锚） |
| SAN | `router.silentcrow.top` / `localhost` / `127.0.0.1` / `::1` / `192.168.88.7` / `192.168.193.215` / `60.186.131.130` |
| 有效期 | 2026-11-02 ~ 2036-10-30 |
| SHA256 | `69289b51cefeda3af35f29cc83f9158ca8f3b687c7bb5eaeebd442e3296e9e3d` |
| 协商结果 | TLSv1.3 / `TLS_AES_128_GCM_SHA256` |

公共 CA 不认它 —— Windows schannel 报 `SEC_E_UNTRUSTED_ROOT`，Python 报
`self-signed certificate`。

**客户端做法：把证书内置成信任锚，不是关闭校验。**

```python
ctx = ssl.create_default_context()                    # 系统 CA + 主机名校验
ctx.load_verify_locations(cadata=LOG_PINNED_CERT_PEM) # 叠加 pin 证书
```

- `load_verify_locations(cadata=...)` 是**叠加**到系统 CA 之上，不是替换
  （`create_default_context(cadata=...)` 才是替换 —— 那样会丢掉公共 CA）。
- `check_hostname` 与 `CERT_REQUIRED` 全程保持开启 → **加密 + 认证**都在。
- 服务端换成公共 CA 签发的证书后，系统信任链直接生效，客户端无需更新。
- 服务端**换证书** = 换信任锚，必须同步更新内置 PEM 并重新发版。

**反面做法**：`CERT_NONE` / `check_hostname=False` —— 那是「加密但不认证」，
中间人可读全部栈信息，等于把 HTTPS 降级成明文的等价物。

| 字段 | 说明 |
|---|---|
| `app` | 固定 `netpulse` |
| `type` | `critical` / `error` / `warn` / `info` / `debug`，缺省 `info` |
| `message` | 一行摘要，含上下文 |
| `stack` | 完整 traceback（可选） |
| `ts` | ISO8601 毫秒 + 时区偏移，缺省为服务端接收时刻；服务端存库归一化为 UTC |
| `os` | 自定义终端标识，提供则覆盖 UA 解析结果 |

鉴权走 `X-Token`。端点与 token 均可��环境变量覆盖（`NETPULSE_LOG_URL` / `NETPULSE_LOG_TOKEN`），
换服务器不必重新打包。

### 2.1 客户端时间戳

**必须客户端带 `ts`**，不用服务端接收时刻 —— 崩溃发生时刻与接收时刻可能相差很久
（机器离线、限流丢弃、重试），排查时需要真实发生时间。

格式：`datetime.now().astimezone().isoformat(timespec="milliseconds")`
→ `2026-11-02T11:29:00.000+08:00`

### 2.2 `os` 字段

用**系统版本串**，不含任何身份信息：

```
Windows 10.0.26100 x64
```

不传 hostname —— 会带出客户机名。

### 2.5 上下文编码

协议没有独立 metadata 字段，上下文编码进 `message`，固定前缀便于服务端机器解析：

```
v1.17.0 [模块:dns] 探测异常 (TimeoutError): socket timeout
v1.17.0 [线程:monitor-probe] 探测循环异常 (ValueError): ...
v1.17.0 [崩溃] 未预期异常 (ValueError): ...
```

版本号放在 `message` 前缀里 —— 协议没有 version 字段，但按版本看问题分布是优化的基本需求。



| 场景 | 服务端响应 |
|---|---|
| 合法 token + 合法负载 | `200 {"ok":true,"data":{"inserted":1}}` |
| token 缺失或错误 | `401 {"ok":false,"error":"无效 token"}` |
| `type` 不在五个合法值内 | `400 {"ok":false,"error":"第 1 条: type 必须是 critical\|error\|warn\|info\|debug"}` |
| `message` 为空 | `400 {"ok":false,"error":"第 1 条: message 不能为空"}` |
| `ts` 非 RFC3339 | `400 {"ok":false,"error":"第 1 条: ts 需为 RFC3339 格式, 收到 \"...\""}` |
| 缺 `type` | `200` —— 缺省为 `info` |
| 缺 `app` / 多余字段 | `200` —— 不校验，忽略 |
| 非 JSON 体 | `400 {"ok":false,"error":"JSON 解析失败: ..."}` |

**由此确定的三条实现约束**：

1. **单条提交，不用批量**。服务端支持数组（`[{...},{...}]` → `inserted:2`），但实测
   **批量是「全有或全无」** —— 一条不合法整批 400，**所有条目都不入库**。
   批量会把一条坏条目放大成整批丢失，不划算。
2. **错误信息必须透传**。4xx 响应体里的 `error` 是中文可读原因
   （如「第 1 条: message 不能为空」），压成 "HTTP Error 400" 等于丢光排查线索。
   `_post_log` 单独捕获 `HTTPError` 并解析该字段。
3. **客户端必须自己限流**。实测连发 55 条无 429 —— 服务端当前**未实现限流**。
   token 内置在 exe 里、逆向可得，限流是必需防线，现在只有客户端侧的
   「指纹去重 + 单轮预算」在挡。


## 3. 上报范围（已确认）

**只报软件自身问题，不含任何客户网络诊断数据。**

| 级别 | 触发 |
|---|---|
| `critical` | 顶层未捕获异常（程序无法继续） |
| `error` | 模块/探针异常、后台线程静默死亡 |
| `warn` | 内部非致命降级（证据生成失败、报告构建降级） |
| `info` / `debug` | 预留，本次不发 |

**明确不报**：丢包率、延迟、SSID、公网 IP、MAC、诊断结论、客户名。

## 4. 异常捕捉健全性（本次核心）

审计结论：全仓约 45 处吞异常点把异常在到达任何上报通道之前就吃掉了。现有通道只接得住
「逃逸到顶层」的异常，因此**模块级异常 100% 不会进入上报**。

### 4.1 探针路径：异常类型与 traceback 全丢

| 位置 | 现状 |
|---|---|
| `netpulse.py:14878` / `:14922` | 线程内 `box["err"] = e` 保住异常对象 |
| `netpulse.py:14887` / `:14931` | `return "错误", {"error": str(box["err"])}` —— **只剩一句字符串** |
| `netpulse.py:14973` / `:15034` | `except Exception as e: status, res = "错误", {"error": str(e)}` —— 同样只剩字符串 |

后果：即使推上去，服务端收到的也只是 `未预期错误` 这种无信息量的文案，没有异常类型、
没有栈、没有行号 —— 不够定位问题。

**修法**：捕获点立刻 `traceback.format_exc()`，推送时带完整栈。

### 4.2 留存策略

落盘只留元数据，**不留栈**：

```python
res["_exc"] = {"type": "TimeoutError", "message": "...", "scope": "模块:dns"}
```

- `error` 键的值**逐字不变** → 报告文案零变化，健康分口径不变
- `tech.raw_results` 是自由对象（schema `additionalProperties`）→ 不破坏 JSON Schema 校验
- `determine_status()` 只看 `error`/`issues`/`assessment` → 不影响状态判定
- 栈只在推送那一刻用，**不进 `LAST_RUN`、不进客户交付物** → 隐私安全

### 4.3 后台线程静默死亡

盯障探测循环、TCP 统计、MTU 探测、主动负载、ping 读循环、更新检查、上行测速 worker
—— 共 7 处原本 `except Exception: pass`，客户机表现为「没报错但也没结果」。

全部改走统一钩子 `_emit_runtime_event(level, exc, scope)`：写本地日志 + 异步推送。
按指纹限流（同一处同一异常类型最多 3 次），防盯障模式刷屏。

### 4.4 单轮上报预算

全量 23 模块在客户网络全断时会集体失败 → 单轮最多推 5 条模块异常事件。
超预算的只写本地日志。

## 5. 脱敏

在现有「用户目录 / 公网 IP / MAC」基础上补：

| 项 | 方式 | 保证程度 |
|---|---|---|
| 用户目录 | `USERPROFILE` / `~` 精确替换 `<user>` | 可靠 |
| 机器名 | `socket.gethostname()` 精确替换 `<host>` | 可靠（长度 ≥ 4 才替换，避免误伤） |
| SSID | 正则 `SSID[:：=] xxx` → `***` | **尽力而为，不保证 100%** |
| 公网 IP / IPv6 | `_redact_text_value()`（既有口径） | 可靠 |
| MAC | `_mask_mac_text()`（既有口径） | 可靠 |

内网 IP **保留** —— 定位现场问题必需。

## 6. 开关与知情同意

沿用 v1.17.0 在制品的设计，改名与文案：

| 入口 | 行为 |
|---|---|
| 默认 | 开启 |
| 首次运行 | 交互终端弹窗告知上报内容 + 征询同意（告知一次，不反复打扰） |
| 交互菜单 `[C]` | 随时切换 |
| CLI `--log-report on\|off` | 自动化场景用；显式指定后不再弹首次告知 |
| 环境变量 `NETPULSE_LOG_REPORT=0` | 最高优先级的关闭开关 |

配置文件：`%LOCALAPPDATA%\NetPulse\log_report.json`。

非 TTY（管道 / `--json` / 自动化）**静默跳过**弹窗，不污染机器可读输出。

## 7. 健壮性

- 异步上报 + 限时等待（崩溃路径 15s）；网络不通不会拖住用户退出
- 网络失败 / 上报本身抛异常 → 全部降级为「只落盘」，**退出码不变**
- `SystemExit` 与 `KeyboardInterrupt` 不上报（前者正常退出，后者 Ctrl+C）
- 端点不可达时静默失败，不弹提示、不影响任何用户操作

## 8. 删除项

- `deploy/crash_server/`（自建服务端 + README）—— 该端点从未部署，DNS 都不解析
- `crash.silentcrow09.top` 端点、`CRASH_WRITE_KEY`、`CRASH_REPO`、`CRASH_TOKEN_ENV`
- GitHub Issues 兜底通道（`_post_github_issue` / `_crash_issue_body` / `_crash_issue_title`）
- `tests/test_crash_server.py`

## 9. 测试

`tests/test_log_report.py`（替换 `tests/test_crash_report.py`）：

- 协议：payload 字段与取值合法、`X-Token` 头、`ts` 格式、`os` 不含 hostname
- 脱敏：用户名 / 公网 IP / MAC / hostname / SSID 不出现
- 开关：默认开、可关、持久化、env 强制关、非 TTY 静默、CLI on/off
- 限流：同指纹超限不再报；单轮预算生效
- 降级：网络失败 / 401 / 超时 → 不抛、不影响退出码
- 接入：`_cli_entry` 崩溃走通且退出码仍为 3；Ctrl+C 与 SystemExit 不上报
- **探针异常上报含完整 traceback**
- **后台线程钩子触发**
- **协议形状端到端**：本地 mock 服务端（按本文档协议实现）真收一条 POST

全部 mock / 本地，无真实外网依赖。

## 10. 已知风险

1. **服务端目前未实现限流**：实测连发 55 条无 429。token 内置在 exe 里、逆向可得，
   限流是必需防线。现在只有客户端侧的「指纹去重（3 次/指纹/版本）+ 单轮预算
   （5 条/轮）+ 本地日志限频」在挡 —— **服务端侧应补 IP 限流与配额**。
2. **服务端管理接口按来源 IP 限制**：从开发机访问 `/health`、`/v1/logs` 等
   一律 `403 该来源不允许访问管理接口`（写入接口不受影响）。运维看板需在
   服务端放行来源。
3. **服务端是自签证书**：客户端靠内置 pin 证书认证。换证书需重新发版；
   建议服务端后续改用公共 CA 证书，届时客户端无需更新即可继续工作。
4. **企业 MITM 代理环境**：若客户机的企业代理解密 HTTPS 并重新签发证书，
   pin 校验会失败 → 上报静默降级为「只写本地日志」（不影响诊断功能）。
   这是 pin 的固有取舍。
5. **SSID 脱敏是尽力而为**：只覆盖 `SSID: xxx` 这类带标签的写法，无法保证
   100%。用户目录、机器名、公网 IP、MAC 是可靠替换。


