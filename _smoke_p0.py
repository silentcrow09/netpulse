"""P0 修复后的静态冒烟测试。"""
import sys
import os
sys.path.insert(0, r"D:\Work\Projects\NetPulse")
import netpulse as n

print("=== Test 1: _get_local_subnet 缓存 + 回退 ===")
n._LOCAL_SUBNET_CACHE.clear()

# 合法 IPv4 (会真跑 powershell, 失败时回退)
print("  192.168.1.100 ->", n._get_local_subnet("192.168.1.100"))
# 不合法 IP
print("  not.an.ip    ->", n._get_local_subnet("not.an.ip"))
# 127.0.0.1
print("  127.0.0.1    ->", n._get_local_subnet("127.0.0.1"))
# 空
print("  empty        ->", n._get_local_subnet(""))
# 二次调用应该走缓存
r1 = n._get_local_subnet("10.0.0.1")
r2 = n._get_local_subnet("10.0.0.1")
print(f"  cache hit: {r1 is r2}  (r1={r1})")

print()
print("=== Test 2: _report_dir 路径 ===")
d = n._report_dir()
print(f"  报告目录: {d}")
print(f"  exists: {os.path.isdir(d)}")
print(f"  is writable: {os.access(d, os.W_OK)}")

print()
print("=== Test 3: 源码关键改动确认 ===")
src = open(r"D:\Work\Projects\NetPulse\netpulse.py", encoding="utf-8").read()
checks = [
    ("getattr(sys, \"frozen\", False)", "frozen 检测"),
    ("except OSError", "回退到 USERPROFILE"),
    ("MAX_INDETERMINATE", "MTU 无信号上限"),
    ("path_mtu\": None", "MTU 失败返回 None"),
    ("r.get(\"error\")", "MTU error 字段处理"),
    ("_get_local_subnet", "P0#3 子网函数"),
    ("PrefixLength", "PowerShell 取 prefix length"),
    ("wifi_rate_low", "P0#4 WiFi 低速 issue"),
    ("ethernet_rate_low", "P0#4 有线低速 issue"),
    ("all_first_hops_timed_out", "P0#5 全超时报警"),
    ("timed_out_targets", "P0#5 区分首跳"),
]
for needle, desc in checks:
    found = needle in src
    print(f"  [{'OK' if found else 'MISS'}] {desc}: '{needle}'")

print()
print("=== Test 4: determine_status 关键词覆盖 ===")
# 验证 determine_status 仍能识别新的 assessment 关键词
from netpulse import determine_status
# 极低速 WiFi 关键词 "过低"
r1 = {"assessment": "WiFi 速率过低"}
r2 = {"issues": [{"severity": "warning", "message": "x"}]}
r3 = {"issues": [{"severity": "critical", "message": "x"}]}
print(f"  'WiFi 速率过低'  -> {determine_status(r1)} (期望: 警告)")
print(f"  warning issue    -> {determine_status(r2)} (期望: 警告)")
print(f"  critical issue   -> {determine_status(r3)} (期望: 异常)")

print()
print("ALL DONE")
