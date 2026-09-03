#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetPulse - Windows 网络诊断工具
单文件便携版 v1.0.0

功能模块 (23 项, 序号与 --list 一致):
  基础信息:  链路速率 / DHCP / LAN 扫描 / WiFi / IPv6 / 多出口
  宽带测速:  测速 / Bufferbloat / iperf3 吞吐 / TCP 并发 (NAT 表上限压测)
  故障诊断:  网关 / 外网 / DNS / 网页体检 (L7 分段) / ARP / 环路 / TCP 连接 /
             端口探测 / 路由表 / TCP 传输质量 / MTU / 代理检测 / NAT 类型 (STUN)
"""

# ============================================================
# SECTION 1: IMPORTS
# ============================================================

# 抑制 scapy 导入时的 cryptography DH 弃用警告 (scapy 内部问题，不影响功能)
import warnings
warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*deprecated.*")

import subprocess
import threading
import ctypes
import socket
import struct
import time
import json
import os
import re
import sys
import unicodedata
import argparse
import tempfile
import ipaddress
import shutil
import zipfile
from bisect import bisect_left
from datetime import datetime
from collections import defaultdict, Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.parse import urlsplit, urlunsplit, urljoin
import http.client
import ssl
import asyncio
import webbrowser

# 可选依赖 — 缺失时自动降级
#
# v1.9.7 PR-2 (scapy 懒加载): scapy.all 导入在实机占 0.6-1.5s (含 cryptography
# 缺失探测与 manufdb 解析), 是「双击启动到菜单 5-6s」的主要组成之一。改为
# 占位符 + 后台预加载: main() 一进来就开 daemon 线程导 scapy, 菜单先渲染;
# 任何用到 scapy 的函数入口先 _ensure_scapy() 等预加载收尾 (通常菜单渲染时
# 已加载完, 用户选完模块零等待)。名字绑定用 _load_scapy() 统一写入模块
# globals, 与 ensure_scapy() 安装后的 _reload_scapy() 复用同一条路径。
# 注意: SCAPY_AVAILABLE 在预加载完成前为 False, 判定前必须先 _ensure_scapy()。
SCAPY_AVAILABLE = False  # True = scapy 已导入并绑定到下方名字
SCAPY_LOADED = threading.Event()  # 名字绑定完成信号 (成功或失败都会置位)

Ether = IP = UDP = TCP = DNS = DHCP = BOOTP = ICMP = ARP = None
srp = sendp = sniff = conf = sr1 = None
get_if_list = get_if_addr = get_if_hwaddr = None

_scapy_thread = None  # 后台预加载线程 (main() 启动; 测试可手动触发)


def _load_scapy():
    """导入 scapy.all 并把名字绑定到模块 globals。返回是否成功。

    供后台预加载线程 / ensure_scapy 安装后的 _reload_scapy 复用。
    成败都会置位 SCAPY_LOADED (Event), 让等待方不再空等。
    """
    global SCAPY_AVAILABLE, Ether, IP, UDP, TCP, DNS, DHCP, BOOTP, ICMP, ARP
    global srp, sendp, sniff, conf, sr1, get_if_list, get_if_addr, get_if_hwaddr
    try:
        from scapy.all import (
            Ether, IP, UDP, TCP, DNS, DHCP, BOOTP, ICMP, ARP,
            srp, sendp, sniff, conf, sr1, get_if_list, get_if_addr, get_if_hwaddr
        )
        SCAPY_AVAILABLE = True
    except Exception:
        SCAPY_AVAILABLE = False
    finally:
        SCAPY_LOADED.set()
    return SCAPY_AVAILABLE


def _ensure_scapy(timeout=20):
    """确保 scapy 已导入 (等后台预加载收尾, 未启动过则同步加载一次)。

    返回 SCAPY_AVAILABLE。所有直接引用 scapy 裸名 (Ether/TCP/conf/...)
    的函数入口必须先调用本函数, 否则会拿到占位符 None。
    """
    if not SCAPY_LOADED.is_set():
        t = _scapy_thread
        if t is not None and t.is_alive():
            t.join(timeout)
        if not SCAPY_LOADED.is_set():
            _load_scapy()
    return SCAPY_AVAILABLE


def _start_scapy_preload():
    """启动后台预加载线程 (main() 入口调用一次; 重复调用幂等)。"""
    global _scapy_thread
    if FORCE_NO_SCAPY or SCAPY_LOADED.is_set():
        return
    if _scapy_thread is None or not _scapy_thread.is_alive():
        _scapy_thread = threading.Thread(
            target=_load_scapy, name="scapy-preload", daemon=True)
        _scapy_thread.start()

# 强制禁用 scapy 二层抓包 (某些机器 Npcap 不稳定会段错误): 置 True 后 DHCP 走 ipconfig 降级
FORCE_NO_SCAPY = False

# Ookla Speedtest CLI (speedtest.exe) 可用性 — 运行时按需探测 (见 _find_ookla_speedtest)。
# 旧版用 speedtest-cli Python 库 (import speedtest), 但国内常选海外服务器结果严重偏低,
# 已替换为 Ookla 官方 CLI (支持 -s <id> 指定国内服务器, 输出含丢包/jitter/result_url)。
# 兼容: 保留 SPEEDTEST_LIB_AVAILABLE 别名 (旧代码引用), 实际指向 OOKLA_AVAILABLE。
OOKLA_AVAILABLE = None  # None=未探测, True/False=已探测
SPEEDTEST_LIB_AVAILABLE = OOKLA_AVAILABLE  # 别名 (向后兼容)

# ============================================================
# SECTION 1b: 可选依赖自动安装 (scapy / Npcap)
# ============================================================

# scapy 安装提示状态机 (避免重复问, 也允许 --install 后重新尝试)
# - NEVER_OFFERED: 从未问过 (首次 dhcp 缺失时进入提问)
# - USER_DECLINED: 交互式问过, 用户拒绝 (本次会话不再问, 除非 auto_yes)
# - USER_ACCEPTED: 用户接受 (已开始装)
# - INSTALLED: 已装好
SCAPY_OFFER_STATE_NEVER = "never"
SCAPY_OFFER_STATE_DECLINED = "declined"
SCAPY_OFFER_STATE_ACCEPTED = "accepted"
SCAPY_OFFER_STATE_INSTALLED = "installed"
SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_NEVER

# 最近一次诊断运行的完整数据 (供报告生成使用)
LAST_RUN = None

# 模块运行参数统一配置 (阶段 B · v1.2.0 引入 — B12)
# 设计: 把散落各模块的 XXX_CONFIG 集中到顶层 CONFIG 字典, 按模块名分 key.
#       旧名字 (PORT_PROBE_CONFIG 等) 作为 alias 指向 CONFIG 子项, 旧代码不改
#       即可继续工作 (Python dict 引用, 修改 alias 等同修改 CONFIG 子项).
#
# Ookla 上海电信服务器 ID 3633 来源: speedtest.net 官方服务器列表
# (https://www.speedtest.net/server/3633), 长期稳定; 如失效可 --speedtest-node 覆盖
OOKLA_DEFAULT_SERVER_ID = 3633  # 上海电信

CONFIG = {
    # 端口探测模块的运行参数 (由 CLI --port-* 写入, run_diagnostics 读取)
    "port": {"targets": [], "proto": "tcp", "count": 2,
             "force": False, "max_total_time": 60.0,
             "max_concurrency": 8},
    # 测速 / iperf3 模块的运行参数
    # - iperf3_server / iperf3_port / iperf3_duration: iperf3 独立模块用, 由 --iperf3-server 提供;
    #   提供后 iperf3 模块测到该服务器的上下行吞吐 (iperf3 是最准的链路吞吐测量)
    # - use_speedtest_net: 默认启用 — Ookla Speedtest CLI 官方测速作为对照参考;
    #   交互菜单模式下自动启用 (无需 --speedtest-net), CLI 模式需显式加 --speedtest-net
    # - ookla_server_id: 默认 3633 (上海电信 Ookla 服务器), 避免自动选点偏海外;
    #   --speedtest-node <数字ID> 可覆盖; 传 host:port 则只影响国内上行节点
    # - node: 手动指定测速服务器 — 数字 ID (Ookla 服务器, 配合 --speedtest-net) 或
    #   host:port (国内上行节点); 默认自动选国内运营商节点
    # - duration_down / duration_up: 上下行测速时长 (秒)
    # - live_ui: 单独运行测速模块时启用终端实时可视化 (由 run_diagnostics 写入)
    "speedtest": {"iperf3_server": None, "iperf3_port": 5201, "iperf3_duration": 10,
                  "use_speedtest_net": False,
                  "ookla_server_id": OOKLA_DEFAULT_SERVER_ID,
                  "node": None, "duration_down": 8.0, "duration_up": 8.0,
                  "live_ui": False},
    # NAT 类型模块的运行参数 (由 CLI --nattype-server 写入, runner 读取)
    # 为空时用内置候选 (实测可用的排前), 给 1~2 台则覆盖
    "nattype": {"servers": []},
    # 网页体检模块的运行参数 (由 CLI --web-target 写入, 追加到默认 3 目标后)
    "web": {"targets": []},
    # TCP 并发模块的运行参数 (由 CLI --tcpcc-max / --tcpcc-target 写入)
    # - max: 阶梯上限 (默认 1600, 硬上限 8000; Windows 临时端口 ~16k, 高上限勿短时重复跑)
    # - target: 自定义目标 host:port (默认自动挑公网 anycast DNS 的 TCP 53)
    "tcpcc": {"max": 1600, "target": None},
}

# 兼容性 alias (B12): 旧名字指向 CONFIG 子项, 旧代码不改即可继续工作
# 写 PORT_PROBE_CONFIG["targets"] = xxx 实际修改 CONFIG["port"]["targets"]
PORT_PROBE_CONFIG = CONFIG["port"]
SPEEDTEST_CONFIG = CONFIG["speedtest"]
NATTYPE_CONFIG = CONFIG["nattype"]
WEB_CONFIG = CONFIG["web"]
TCPCC_CONFIG = CONFIG["tcpcc"]


def _is_admin():
    """检测当前是否以管理员权限运行 (安装 Npcap 需要)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ============================================================
# 自提权重启 (v1.9.7 PR-3)
# ============================================================
# 解决「普通权限启动 → 发现需要管理员 → 手动关闭 → 右键管理员运行」的断档。
# 设计取舍:
#  - manifest 保持 asInvoker (双击不弹 UAC): 大多数诊断不需要管理员,
#    每次启动都提权是 UAC 疲劳 + 普通用户会吓到。
#  - 需要管理员的功能点 (Npcap 安装 / 抓包取证 / 菜单 [A]) 一键自提权:
#    ShellExecuteW("runas") 弹 UAC, 新窗口以管理员运行并接续当前意图,
#    旧窗口 sys.exit(0) 退出。
#  - 提权重启优先经 Windows Terminal 启动: 提权后默认开的是新 conhost
#    实例 (黑底默认样式), 与用户配好的 WT 主题不一致; 显式走 wt.exe
#    可让两种权限下窗口样式统一。wt 不可用时回退直接启动 exe。


def _find_windows_terminal():
    """定位 Windows Terminal (wt.exe)。返回路径或 None。

    wt.exe 是 Store 应用执行别名, 在 PATH (%LOCALAPPDATA%\\Microsoft\\
    WindowsApps) 里; shutil.which 覆盖该目录。
    """
    try:
        return shutil.which("wt.exe") or shutil.which("wt")
    except Exception:
        return None


def _self_exe_path():
    """本程序可执行文件绝对路径 (frozen: sys.executable; 源码跑: python + 脚本)。"""
    if getattr(sys, "frozen", False):
        return sys.executable
    return sys.argv[0] if os.path.isabs(sys.argv[0]) else \
        os.path.abspath(sys.argv[0])


def _build_elevated_launch(args_tail=None, workdir=None):
    """构造提权启动参数 (纯函数, 便于测试)。返回 (lp_file, lp_params)。

    直接对应 ShellExecuteW(None, "runas", lp_file, lp_params, ...):
      - wt 可用: lp_file=wt.exe, lp_params='-d "<workdir>" "<exe>" <tail>'
        (WT 会用用户默认 profile 渲染, 样式与普通权限一致)
      - 无 wt: frozen 时 lp_file=本 exe; 源码运行 lp_file=python.exe
    - args_tail 里含空格的项自动加引号 (路径类参数)
    - 源码运行 (非 frozen): 用 python.exe 启动脚本, 不依赖文件关联
    """
    args_tail = [str(a) for a in (args_tail or [])]
    tail = " ".join(f'"{a}"' if (" " in a and not (a.startswith('"') and a.endswith('"')))
                    else a for a in args_tail)
    exe = _self_exe_path()
    if getattr(sys, "frozen", False):
        lp_file, lp_params = exe, tail
    else:
        lp_file = sys.executable
        lp_params = f'"{exe}"' + (f" {tail}" if tail else "")
    wt = _find_windows_terminal()
    if wt:
        wd = workdir or os.getcwd()
        inner = lp_params if not getattr(sys, "frozen", False) \
            else f'"{lp_file}"' + (f" {lp_params}" if lp_params else "")
        return wt, f'-d "{wd}" {inner}'
    return lp_file, lp_params


def _relaunch_elevated(args_tail=None):
    """以管理员身份重启本程序 (UAC 由 ShellExecuteW 弹出)。

    返回 (ok, msg): ok=True 表示已成功发起提权启动, 调用方应尽快
    sys.exit(0) 让位; ok=False 表示用户取消或系统拒绝, msg 给提示文案。
    """
    try:
        lp_file, lp_params = _build_elevated_launch(args_tail)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", lp_file, lp_params, None, 1)  # SW_SHOWNORMAL
        if ret > 32:
            return True, "已发起管理员权限启动"
        return False, (f"Windows 拒绝提权 (ShellExecuteW 返回 {ret}): "
                       "用户取消 UAC 或策略禁止; 可右键\"以管理员身份运行\"重试")
    except Exception as e:
        return False, f"提权重启失败: {e} (可右键\"以管理员身份运行\"重试)"


def _offer_elevation_relaunch(args_tail=None, reason="", input_fn=None):
    """提示并 (确认后) 以管理员身份重启。成功重启 → sys.exit(0)。

    reason: 一句话说明为什么要管理员 (会展示给用户)。
    用户取消 / 提权失败: 打印降级提示后正常返回, 不打断当前流程。
    """
    if not sys.stdin.isatty():
        return  # 非交互 (脚本/管道): 只静默跳过, CLI 用户自己控制提权
    input_fn = input_fn or input
    print()
    print(_c(f"  ⚠ {reason}", C_YELLOW))
    try:
        ans = input_fn(_c("  以管理员身份重启 NetPulse 继续? [y/N] ", C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if ans not in ("y", "yes"):
        print(_c("  已跳过。当前窗口继续以普通权限运行。", C_GRAY))
        return
    ok, msg = _relaunch_elevated(args_tail)
    if ok:
        print(_c("  ✓ UAC 确认后将打开新的管理员窗口, 本窗口即将退出...", C_GREEN))
        sys.exit(0)
    print(_c(f"  ✘ {msg}", C_YELLOW))


# ============================================================
# 修复命令一键执行 (v1.9.8 · 遗留项 1)
# ============================================================
# 根因建议里带 "(管理员)" 标记的命令 (目前唯一生产者: MTU 黑洞规则的
# netsh 接口 MTU 修复)。交互式诊断打印完后提供一键执行: UAC 确认后在
# 独立管理员 cmd 窗口运行 (cmd /k 保持窗口), NetPulse 本身不动系统配置。
# 只提取、不代写命令 — 命令文本仍来自规则建议, 与报告显示逐字一致。


_ADMIN_FIX_RE = re.compile(r"netsh\s+(.+?)\s*\(管理员\)")


def _extract_admin_fix_commands(root_causes):
    """从根因建议里提取带 "(管理员)" 标记的 netsh 命令 (去重保序)。

    只认 "(管理员)" 尾标的命令段 — 这是规则建议的既定格式
    (参考 _rule_mtu_blackhole), 不做猜测式提取, 避免误执行。
    返回命令体列表 (不含 "netsh " 前缀, 展示/执行时统一补)。
    """
    cmds, seen = [], set()
    for rc in (root_causes or []):
        for rec in (getattr(rc, "recommendations", None) or []):
            m = _ADMIN_FIX_RE.search(str(rec))
            if not m:
                continue
            cmd = m.group(1).strip().rstrip("，,;；")
            if cmd and cmd not in seen:
                seen.add(cmd)
                cmds.append(cmd)
    return cmds


def _offer_admin_fix_shell(commands, input_fn=None):
    """交互式提议以管理员身份执行修复命令 (cmd /k, 窗口保持可核对)。

    commands: _extract_admin_fix_commands 的结果 (命令体, 无 netsh 前缀)。
    返回实际发起执行的命令数 (用户跳过/取消 → 0)。
    非 TTY 直接跳过 (脚本/管道不打断)。
    """
    if not commands or not sys.stdin.isatty():
        return 0
    input_fn = input_fn or input
    print()
    print(_c(f"  ⚠ 发现 {len(commands)} 条管理员修复命令 "
             f"(将以管理员权限修改系统配置, 改完可复测验证):", C_YELLOW))
    for i, cmd in enumerate(commands, 1):
        print(_c(f"    [{i}] netsh {cmd}", C_WHITE))
    hint = "  输入要执行的序号 (逗号分隔, Enter=跳过): "
    try:
        ans = input_fn(_c(hint, C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if not ans:
        return 0
    picked = []
    for tok in ans.replace("，", ",").split(","):
        tok = tok.strip()
        if tok.isdigit() and 1 <= int(tok) <= len(commands):
            c = commands[int(tok) - 1]
            if c not in picked:
                picked.append(c)
    launched = 0
    for cmd in picked:
        try:
            # cmd /k: 执行后窗口保持打开, 用户能核对结果/错误码再关闭;
            # runas: 已是管理员时 UAC 不弹窗, 静默放行
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "cmd.exe", f"/k netsh {cmd}", None, 1)
            if ret > 32:
                launched += 1
            else:
                print(_c(f"  ✘ [{launched + 1}] Windows 拒绝提权 "
                         f"(ShellExecuteW 返回 {ret})", C_YELLOW))
        except Exception as e:
            print(_c(f"  ✘ 执行发起失败: {e}", C_YELLOW))
    if launched:
        print(_c(f"  ✓ 已发起 {launched} 个管理员命令窗口 "
                 f"(执行完请回到 NetPulse 复测验证)", C_GREEN))
    return launched


def _is_broadcast_or_reserved_ip(ip):
    """判断 IP 是否是广播/组播/保留 (用于 ARP 表多 IP 同 MAC 场景)。

    与 _is_valid_unicast_mac 互补: 那个判断 MAC 端, 这个判断 IP 端。
    ARP 表里 "ff-ff-ff-ff-ff-ff -> 192.168.56.255 / 100.70.255.255 /
    255.255.255.255" 都是这种类型, 在判断"网关 MAC 是不是被多个真实设备
    共用"之前必须先排除。

    规则:
      - 255.255.255.255 — 本地有限广播
      - x.x.x.255 / x.x.x.0 / 子网定向广播 — 子网广播 (子网号 + 全 1 主机号)
        简化判断: 末位 255 且不是 1.2.3.255 这种合法主机 (更严的判断需知
        prefix length, 但实际 ARP 表里出现 .255 的基本都是子网广播)
      - 224.0.0.0/4 — IPv4 组播
      - 127.0.0.0/8 — loopback
      - 0.0.0.0 — 未指定地址
    """
    if not ip:
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return True  # 解析不了当作异常值排除
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        return True
    # 末位 255 — 子网定向广播
    if (int(addr) & 0xFF) == 0xFF:
        return True
    return False


# 已知的"假网关"地址 (VPN 客户端为绕过 Windows 网络分类限制而插入的占位默认路由)
# 特点: 地址本身不可达, metric 极高 (10000+), 仅作 Windows 网络栈分类触发用。
#
#  - 25.255.255.254: ZeroTier 在 Windows 上加的占位默认路由
#    * 用途: Windows 网络栈需要默认网关才能正确给网卡分类 (公共网络/专用网络),
#      分类结果决定 Windows 防火墙应用哪套规则。ZeroTier 虚拟网卡没真实网关,
#      所以人为插入一个不可达地址让 Windows 完成分类, 避免防火墙规则失效。
#    * 选段: 25.0.0.0/8 是英国国防部历史保留段 (MOD), 当前未分配给任何国家/组织,
#      公网上不可能真实存在, 不会与真实环境冲突。
#    * 副作用: metric 极高 (通常 10000+), 只有物理链路全失效时才会被选中,
#      此时自然不可达, 不影响正常使用。
#
#  - 240.0.0.0/4 (RFC 1112 IETF 协议保留) 也常被 VPN 用作占位
#    (Tailscale/WireGuard 等类似机制, 段内任何地址都不可达)
#
# 遇到这些地址时, 不应报警告/异常, 也不应去 ping。
_KNOWN_FAKE_GATEWAY_IPS = frozenset({"25.255.255.254"})


def _is_known_fake_gateway(gateway, metric=None):
    """判断一个默认路由的 gateway 是否是"假网关"占位 (VPN 客户端为触发 Windows
    网络栈分类而插入的不可达地址)。

    判定: gateway 在 _KNOWN_FAKE_GATEWAY_IPS 集合内, 或 gateway 处于
    240.0.0.0/4 (IETF 协议保留段), 且 metric 通常 >= 1000 (极低优先级, 不可能
    真的承担流量转发)。
    """
    if not gateway:
        return False
    if gateway in _KNOWN_FAKE_GATEWAY_IPS:
        return True
    try:
        addr = ipaddress.IPv4Address(gateway)
    except Exception:
        return False
    # 240.0.0.0/4 — IETF 协议保留 (RFC 1112), 永远不可达
    if ipaddress.IPv4Address("240.0.0.0") <= addr <= ipaddress.IPv4Address("255.255.255.254"):
        return True
    # 其它未分配段如有需要可在这里加
    return False


# VPN 客户端常见虚拟接口名关键字 (Tailscale / ZeroTier / Wireguard 等)
# 匹配到的话, 对应接口的默认路由通常是"假网关"或 VPN 内部地址,
# 不能直接 ping (要么不可达, 要么走 VPN 隧道, 都会误报)
_VPN_INTERFACE_KEYWORDS = (
    "zerotier", "tailscale", "wireguard", "wg", "tap", "tun",
    "nordvpn", "expressvpn", "surfshark", "protonvpn", "windscribe",
    "hamachi", "lan-turtle", "openconnect", "anyconnect",
    "default",  # Windows route print 对某些 VPN 虚拟接口显示为 "Default" 而不是接口名
)


def _is_vpn_interface(interface_name):
    """判断 default_routes 里的 interface 字段是否指向 VPN 虚拟接口。"""
    if not interface_name:
        return False
    name = interface_name.lower()
    if name == "default":  # VPN 虚拟接口常见空字符串/默认值
        return True
    return any(kw in name for kw in _VPN_INTERFACE_KEYWORDS)


def _is_valid_unicast_mac(mac):
    """判断 MAC 地址是否是"有效单播" (排除广播/组播)。

    规则依据 IEEE 802 + IANA:
      - 00:00:00:00:00:00 — 无效 (ARP 残留/未初始化)
      - ff:ff:ff:ff:ff:ff — 广播 (L2)
      - 最低字节位 (I/G bit) = 1 — 多播
        包括 01:00:5e:xx:xx:xx (IPv4 组播, OUI 00:00:5e)
        包括 33:33:xx:xx:xx:xx (IPv6 组播, OUI 33:33)
        包括 01:80:c2:xx:xx:xx (LLDP/MSTP/802.1X/CDP/PVST 等协议保留,
          IANA 分配的 OUI 本身多播位=1, 协议用多播地址实现,
          不会出现在 IP ARP 表里)
        包括 ff:xx:xx:xx:xx:xx 等所有多播
      - 其它 (X0/X2/X4/X6/X8/XA/XC/XE 前缀的单播 OUI) — 视为正常设备

    这是 ARP 表分析 (LoopDetector / ARPAnalyzer / LANDeviceScanner) 的
    关键过滤: 不做这一步会把"一个广播 MAC 对应多个子网广播 IP"或
    "一个组播 MAC 对应多个组播组 IP"误判为"交换机/环路"。
    """
    if not mac or not isinstance(mac, str):
        return False
    # 规范化: 接受 "aa-bb-cc..." 或 "aa:bb:cc..." 两种格式
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    try:
        b = [int(x, 16) for x in parts]
    except ValueError:
        return False
    # 全 0 / 全 1
    if all(x == 0 for x in b):
        return False
    if all(x == 0xFF for x in b):
        return False
    # 多播位 (I/G bit = 最低字节最低位) — 一次性覆盖广播/组播/IPv4组播/
    # IPv6组播/协议保留 (LLDP/MSTP 等), 不需要再写 01:80:c2 那种 dead code
    if b[0] & 0x01:
        return False
    return True


def _net_ok(host="pypi.org", port=443, timeout=6):
    """检测网络连通性 — 注意企业/受限网络环境可能不通"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _npcap_installed():
    """检测 Npcap 是否已安装 (Windows 上 scapy 二层收发需要它)"""
    try:
        if (os.path.isdir(r"C:\Windows\System32\Npcap") or
                os.path.isdir(r"C:\Windows\SysWOW64\Npcap")):
            return True
    except Exception:
        pass
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap") as k:
            winreg.QueryValueEx(k, "Version")
            return True
    except Exception:
        pass
    return False


def _urlopen_with_proxy(url, timeout=120, ua="NetPulse/1.0"):
    """带环境变量代理支持的下载 (兼容企业代理网络)。

    ua: User-Agent 字符串, 默认 "NetPulse/1.0"。个别站点 (如 mac.bmcx.com)
    对非浏览器 UA 响应异常, 调用方可传入浏览器 UA。
    """
    import urllib.request as ur
    proxies = {}
    for env_key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        val = os.environ.get(env_key)
        if val:
            scheme = env_key.lower().split("_")[0]
            proxies[scheme] = val
    handlers = [ur.ProxyHandler(proxies)] if proxies else []
    opener = ur.build_opener(*handlers)
    req = Request(url, headers={"User-Agent": ua})
    return opener.open(req, timeout=timeout)


def _pip_install_scapy(mirror=None):
    """用当前解释器安装 scapy。返回 (ok, msg)。

    mirror: 显式指定的 pip 镜像 URL; None 时由 _resolve_pip_mirror 自动选源。
    """
    # PyInstaller 打包的 exe 没有 pip; scapy 已通过 --collect-all 打进 exe,
    # 此处直接成功返回, 避免误报 "pip 安装失败"。
    if getattr(sys, "frozen", False):
        try:
            import scapy.all  # noqa: F401
            return True, "scapy 已随 exe 打包 (--collect-all scapy)"
        except Exception as e:
            return False, (f"scapy 导入失败 (PyInstaller 打包不完整?): {e}\n"
                           f"请重新运行 build_exe.bat 重新打包。")
    if mirror is None:
        mirror, source = _resolve_pip_mirror()
        if mirror:
            print(_c(f"  自动选源: {mirror} ({source})", C_GRAY))
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "scapy"]
    if mirror:
        cmd += ["-i", mirror]
    env = os.environ.copy()
    # 企业代理: 传递 HTTPS_PROXY/HTTP_PROXY 给 pip
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                              timeout=420)
    except subprocess.TimeoutExpired:
        return False, "pip 安装超时 (可能是网络较慢或受限网络环境)"
    except Exception as e:
        return False, f"pip 安装异常: {e}"
    out = (proc.stdout + proc.stderr).strip()[-1500:]
    if proc.returncode != 0:
        return False, out or "pip 返回非零退出码"
    return True, out


# ============================================================
# SECTION 1c: V2 CORE MODELS  (阶段 A · v1.1.0 引入)
# ============================================================
# 设计目标: 把"散落 dict"变成"有名字的对象", 不动对外行为
# 现有 STATUS_KEY / STATUS_COLORS / STATUS_BAR_ORDER 保持兼容, 新模块可选用枚举
# 冻结红线: HTML/CLI/JSON 字段保持完全一致 (_smoke_report.py 全绿, 像素级 HTML 一致)
#
# 不引入 Pydantic/dataclasses-json 等新依赖 — 保持单文件 EXE 形态不变
# 不修改现有 STATUS_KEY 字典 — 旧渲染代码继续按中文字符串取色
# 新枚举/dataclass 仅作"可选新基建", 阶段 B 起再逐步迁移旧模块调用点

from dataclasses import dataclass, field, asdict
from enum import Enum


class Status(Enum):
    """模块级运行状态 — 替代散落字符串 "完成/警告/异常/错误/超时/未检测".

    现有渲染代码按中文字符串取色 (STATUS_KEY["完成"] → "ok"),
    新代码可直接用 Status.OK 等枚举值。
    """
    OK = "ok"
    INFO = "info"
    WARNING = "warn"
    ERROR = "err"
    FATAL = "fatal"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    IDLE = "idle"            # 未检测
    UNKNOWN = "unknown"

    # --- 中文字符串 ↔ 枚举桥接 (供新旧两套代码共存) ---
    @classmethod
    def from_zh(cls, zh_label):
        _ZH_TO_STATUS = {
            "完成": cls.OK, "警告": cls.WARNING,
            "异常": cls.ERROR, "错误": cls.FATAL,
            "超时": cls.TIMEOUT, "未检测": cls.IDLE,
        }
        return _ZH_TO_STATUS.get(zh_label, cls.UNKNOWN)

    @property
    def zh_label(self):
        return _STATUS_ZH.get(self, self.value)

    @property
    def is_problem(self):
        """是否参与问题判定 (默认展开 / 问题计数 / 红色徽章).
        与 PROBLEM_STATUSES = ("警告", "异常", "错误", "超时") 口径一致."""
        return self in (Status.WARNING, Status.ERROR, Status.FATAL, Status.TIMEOUT)


_STATUS_ZH = {
    Status.OK: "完成", Status.WARNING: "警告", Status.ERROR: "异常",
    Status.FATAL: "错误", Status.TIMEOUT: "超时", Status.IDLE: "未检测",
    Status.INFO: "信息", Status.SKIPPED: "已跳过", Status.UNKNOWN: "未知",
}


class Severity(Enum):
    """问题严重度 (Issue 级别)."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(Enum):
    """模块风险等级 — 决定是否需用户确认 / 是否默认跳过."""
    PASSIVE = "passive"      # 只读系统信息 (ipconfig / route / WiFi 信息 / Gateway ping)
    ACTIVE = "active"        # 主动发起网络请求 (DNS 查询 / HTTP / Speedtest)
    STRESS = "stress"        # 高负载 / 持续发包 (TCPCC / iperf3 UDP 高并发)

    @property
    def zh_label(self):
        return _RISK_ZH.get(self, self.value)


_RISK_ZH = {
    RiskLevel.PASSIVE: "只读",
    RiskLevel.ACTIVE: "主动探测",
    RiskLevel.STRESS: "压力测试",
}


@dataclass
class DiagnosticError:
    """统一错误模型 — 替代散落 except Exception: pass.

    错误必须: 被捕获 / 被分类 / 被记录 / 必要时展示 / 不影响其他模块继续运行.
    """
    code: str                       # e.g. "TIMEOUT", "PARSE_FAILED", "CMD_NOT_FOUND"
    category: str                   # e.g. "network", "permission", "parse", "internal"
    message: str
    retryable: bool = True
    severity: Severity = Severity.MEDIUM
    exception_type: str | None = None

    def to_dict(self):
        return {
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "retryable": self.retryable,
            "severity": self.severity.value,
            "exception_type": self.exception_type,
        }


@dataclass
class Evidence:
    """诊断证据 — 任何模块结论必须可追溯到具体观察值.

    示例 (网关 ping):
        Evidence(id="gateway.ping.packet_loss", source="gateway.ping",
                 metric="packet_loss", value=14.3, unit="%",
                 confidence=0.98, metadata={"sent": 7, "received": 6})
    """
    id: str                         # 全局唯一 (惯例: "<module>.<step>.<metric>")
    source: str                     # 数据来源 (模块 key 或子步骤名)
    metric: str                     # 指标名
    value: object
    unit: str | None = None
    timestamp: str = ""             # ISO 8601
    confidence: float = 1.0         # 0.0-1.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Issue:
    """诊断问题 — 模块级或跨模块聚合的故障点.

    HTML/CLI/JSON 不再各自重新解释模块结果, 直接渲染 Issue.to_dict().
    """
    id: str
    severity: Severity
    title: str
    description: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    # None = 无可靠依据不下结论 (审计 P1-02): 旧模块结果没有真实置信度,
    # 不再包装成统一的伪精确数字; 原生规则引擎给出的数值保持不变。
    confidence: float | None = None
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "recommendations": list(self.recommendations),
        }


@dataclass
class DiagnosticResult:
    """模块级诊断结果 — 替代 results[k] = {...} 散落 dict.

    调用约定 (阶段 B 起逐步迁移):
        result = probe.run(context)
        results[k] = result.metrics          # 旧入口 (向后兼容)
        if result.error: ...
        for ev in result.evidence: ...
    """
    module_id: str
    status: Status
    started_at: str = ""                     # ISO 8601
    duration_ms: int = 0
    metrics: dict = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    error: DiagnosticError | None = None

    @property
    def is_problem(self):
        return self.status.is_problem

    def to_dict(self):
        return {
            "module_id": self.module_id,
            "status": self.status.value,
            "zh_status": self.status.zh_label,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "metrics": self.metrics,
            "evidence": [e.to_dict() for e in self.evidence],
            "issues": [i.to_dict() for i in self.issues],
            "error": self.error.to_dict() if self.error else None,
        }


@dataclass
class ModuleMeta:
    """模块元数据 — 替代 MODULE_REGISTRY 字符串三件套 (id, name, category).

    阶段 B 起用于统一模块描述, 阶段 A 暂保留 MODULE_REGISTRY 不动.
    """
    id: str
    name: str
    category: str
    runner: object = None                    # Callable[[], DiagnosticResult]
    timeout: float = 30.0
    risk: RiskLevel = RiskLevel.PASSIVE
    dependencies: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "timeout": self.timeout,
            "risk": self.risk.value,
            "risk_zh": self.risk.zh_label,
            "dependencies": list(self.dependencies),
            "prerequisites": list(self.prerequisites),
        }


# === 兼容性桥接 (阶段 A 不动现有调用点, 阶段 B 再逐步替换) ===
# 新模块可直接用 Status 枚举 + DiagnosticResult dataclass;
# 旧模块继续用散落 dict + STATUS_KEY 字符串映射, 两者并存零冲突.
STATUS_ZH_KEY = {s.value: s.zh_label for s in Status}      # "ok" → "完成"
STATUS_KEY_TO_STATUS = {zh: s for zh, s in                 # "完成" → Status.OK
    [(zh, s) for s in Status for zh in [s.zh_label]]}


# ============================================================
# SECTION 1d: PARSERS  (阶段 B · v1.2.0 引入)
# ============================================================
# 集中 Windows 命令文本解析. 输入 raw text, 输出 typed dataclass.
# 与诊断模块解耦 — 可独立单测. 现有调用点保留, 双轨运行.
# 阶段 B7-B11 再把 gateway / dns / route / arp / wifi 模块迁移到 Probe 契约.
#
# 设计原则:
#   1. 解析器不得依赖中英文 UI 文本 (用 "Physical Address" / "MAC 地址" 等同义字段名兜底)
#   2. 字段缺失返回 None / [], 不抛异常 (Windows 不同版本 / 角色字段不全)
#   3. 中文乱码字段 (cp936 解码错误) 自动 fallback 到 UTF-8

@dataclass
class NetworkAdapter:
    """ipconfig /all 一个网络适配器 (含 VPN 虚拟适配器)"""
    name: str                          # e.g. "WLAN", "本地连接", "VirtualBox Host-Only Network"
    desc: str                          # e.g. "Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC"
    mac: str = ""                      # e.g. "02-4E-5A-B7-2F-A9"
    ipv4: str | None = None
    prefix_len: int | None = None      # ipconfig 不输出 prefix_len, 调用方用 PowerShell 补
    ipv6: str | None = None
    gateway: str | None = None
    dhcp_server: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    media_state: str = "unknown"       # "Media disconnected" / "" (connected)

    @property
    def is_up(self):
        return "disconnected" not in self.media_state.lower()


@dataclass
class RouteEntry:
    """route print 的一条 IPv4 路由项"""
    destination: str                   # "0.0.0.0"
    netmask: str                       # "0.0.0.0"
    gateway: str                       # "On-link" 表示直接路由
    interface_ip: str                  # "172.25.131.131"
    metric: int = 0
    is_onlink: bool = False

    @property
    def is_default(self):
        return self.destination == "0.0.0.0" and self.netmask == "0.0.0.0"


@dataclass
class ArpEntry:
    """arp -a 的一条 ARP 表项"""
    ip: str
    mac: str
    interface_ip: str                  # 所属接口 IP (从 "Interface: <ip> --- 0x<n>" 段落解析)
    type_: str                         # "dynamic" / "static"


@dataclass
class WifiInterface:
    """netsh wlan show interfaces 一个 WiFi 接口"""
    name: str                          # "WLAN"
    state: str                         # "connected" / "disconnected"
    ssid: str | None = None
    bssid: str | None = None
    signal_pct: int | None = None
    channel: int | None = None
    radio: str | None = None
    physical_mac: str | None = None
    description: str | None = None
    guid: str | None = None


# --- 段落正则 (中英文 Windows 段落名都匹配) ---)
_IPCONFIG_SECTION_RE = re.compile(
    r"^(?:Ethernet adapter|Wireless LAN adapter|无线局域网适配器|以太网适配器)"
    r"\s*([^:]+?)\s*:\s*$",
    re.MULTILINE,
)
_ARP_SECTION_RE = re.compile(
    r"(?:Interface|接口):\s+([\d.]+)\s+---\s+0x[0-9a-fA-F]+",
)
_ROUTE_TABLE_RE = re.compile(
    r"IPv4 Route Table.*?^={3,}.*?\n(.*?)(?=^={3,}|\Z)",
    re.MULTILINE | re.DOTALL,
)


def _ipconfig_get(body, label):
    """提取 ipconfig 字段值. label 可中英文 (如 'Physical Address' / 'MAC 地址').

    严格限制到行内 (避免 .+ 跨行贪婪抓到下一字段值), 字段为空返回 None.
    """
    pat = r"(?:" + "|".join(re.escape(lbl) for lbl in label) + r")[\. ]+:[ \t]+([^\r\n]+)"
    m = re.search(pat, body)
    if not m:
        return None
    val = m.group(1).strip()
    return val if val else None


def parse_ipconfig(raw):
    """ipconfig /all 输出 → NetworkAdapter 列表.

    段落分隔: 'Ethernet adapter X:' / 'Wireless LAN adapter Y:'
              / '无线局域网适配器 X:' / '以太网适配器 X:' (中文 Windows)
    字段格式: '字段名 . . . : 值' (中英文都遵循此格式)
    """
    adapters = []
    # 跳过顶部全局段 (Host Name / Primary Dns Suffix 等), 第一个段落前的内容
    sections = _IPCONFIG_SECTION_RE.split(raw)
    # sections[0] = 顶部全局信息, [1::2] = 段落名, [2::2] = 段落 body
    for i in range(1, len(sections), 2):
        name = sections[i].strip()
        body = sections[i + 1]
        # Physical Address (英文) / 物理地址 (中文) 都试
        mac = _ipconfig_get(body, ["Physical Address", "物理地址"])
        ipv4 = _ipconfig_get(body, ["IPv4 Address", "IPv4 地址"])
        ipv6 = _ipconfig_get(body, ["Link-local IPv6 Address", "本地链接 IPv6 地址",
                                    "IPv6 Address", "IPv6 地址"])
        gateway = _ipconfig_get(body, ["Default Gateway", "默认网关"])
        dhcp = _ipconfig_get(body, ["DHCP Server", "DHCP 服务器"])
        # DNS 行可能含 IPv4 + IPv6, 字符类放宽到 [\d.:a-fA-F]
        dns_lines = re.findall(
            r"(?:DNS Servers|DNS 服务器)[\. ]+:\s+([\d.:a-fA-F]+)", body)
        media = _ipconfig_get(body, ["Media State", "媒体状态"]) or ""
        desc = _ipconfig_get(body, ["Description", "描述"]) or ""

        # 剥离 IPv4 后缀 (Preferred) / (Duplicate) 等注释
        if ipv4:
            ipv4 = ipv4.split("(")[0].strip()

        adapters.append(NetworkAdapter(
            name=name, desc=desc, mac=(mac or "").replace("-", ":").lower(),
            ipv4=ipv4, prefix_len=None, ipv6=ipv6,
            gateway=gateway, dhcp_server=dhcp,
            dns_servers=[d.strip() for d in dns_lines],
            media_state=media,
        ))
    return adapters


def parse_route_print(raw):
    """route print 输出 → RouteEntry 列表.

    中英文 Windows 输出格式相同, 5 列空格分隔:
        Network Destination  Netmask  Gateway  Interface  Metric
    On-link 表示直接路由 (无需下一跳).
    """
    entries = []
    m = _ROUTE_TABLE_RE.search(raw)
    if not m:
        return entries
    table = m.group(1)
    for line in table.splitlines():
        line = line.strip()
        if not line or not line[0].isdigit():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        dest, mask, gw, iface, metric = parts[:5]
        try:
            metric_int = int(metric)
        except ValueError:
            continue
        entries.append(RouteEntry(
            destination=dest, netmask=mask,
            gateway=gw, interface_ip=iface,
            metric=metric_int, is_onlink=(gw.lower() == "on-link"),
        ))
    return entries


def parse_arp_a(raw):
    """arp -a 输出 → ArpEntry 列表.

    段落分隔: 'Interface: <ip> --- 0x<n>' (英文) / '接口: <ip> --- 0x<n>' (中文).
    表头行 ('Internet Address' / 'Internet 地址') 靠首列必须是 IPv4 自然过滤.
    type 保留原文小写: 英文系统 dynamic/static, 中文系统 动态/静态.
    """
    entries = []
    parts = _ARP_SECTION_RE.split(raw)
    # parts[0] = 顶部, [1::2] = interface_ip, [2::2] = body
    for i in range(1, len(parts), 2):
        iface_ip = parts[i]
        body = parts[i + 1]
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            cols = line.split()
            if len(cols) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", cols[0]):
                ip, mac, type_ = cols[0], cols[1], cols[2]
                entries.append(ArpEntry(
                    ip=ip, mac=mac.lower(),
                    interface_ip=iface_ip,
                    type_=type_.lower(),
                ))
    return entries


# netsh wlan show interfaces 字段名双语别名 (中文 Windows 输出中文字段名,
# SSID/BSSID/GUID 为协议名保持原样). LinkSpeedDetector 的行内解析已按双语
# 处理, 此表让 parser 与之口径一致, 不再分叉.
_NETSH_WLAN_FIELD_ALIASES = {
    "name":         ("Name", "名称"),
    "description":  ("Description", "描述"),
    "guid":         ("GUID",),
    "physical_mac": ("Physical address", "物理地址"),
    "state":        ("State", "状态"),
    "ssid":         ("SSID",),
    "bssid":        ("BSSID",),
    "signal":       ("Signal", "信号"),
    "channel":      ("Channel", "通道"),
    "radio":        ("Radio type", "无线电类型"),
}


def parse_netsh_wlan_interfaces(raw):
    """netsh wlan show interfaces → WifiInterface 列表.

    中英文字段名都认 (英文 Name/State/..., 中文 名称/状态/...).
    注意 netsh 行尾用 \\r\\r\\n (双 \\r 怪异行为), 不归一化会被 \\s+ 误判为多行.

    netsh 实际格式是"每个字段单独一段" (每个字段后有空行), 不按接口分组.
    累积所有字段为一个 interface dict. 一次调用只输出当前接口.
    多行字段值 (如 "Hardware On\\nSoftware Off" / "硬件打开\\n软件关闭") 用 " | " 连接.
    """
    raw = raw.replace("\r\r\n", "\n").replace("\r\n", "\n")
    fields = {}
    for line in raw.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if not k:
            continue
        # 多行字段值累积
        if k in fields:
            fields[k] += " | " + v.strip()
        else:
            fields[k] = v.strip()

    def _f(canonical):
        for alias in _NETSH_WLAN_FIELD_ALIASES[canonical]:
            if fields.get(alias):
                return fields[alias]
        return None

    # 没有 Name/名称 字段说明不是有效接口输出
    # (e.g. 仅 "There is N interface" / "系统上有 N 个接口" 头部)
    name = _f("name")
    if not name:
        return []
    sig_pct = None
    sig_raw = _f("signal")
    if sig_raw:
        mm = re.search(r"(\d+)%", sig_raw)
        sig_pct = int(mm.group(1)) if mm else None
    channel = None
    ch_raw = _f("channel")
    if ch_raw:
        try:
            channel = int(ch_raw)
        except ValueError:
            pass
    return [WifiInterface(
        name=name,
        state=_f("state") or "",
        ssid=_f("ssid"),
        bssid=_f("bssid"),
        signal_pct=sig_pct,
        channel=channel,
        radio=_f("radio"),
        physical_mac=_f("physical_mac"),
        description=_f("description"),
        guid=_f("guid"),
    )]


# ============================================================
# SECTION 1e: PROBES  (阶段 B · v1.2.0 引入 — B7 gateway 试点)
# ============================================================
# 模块契约 (Probe) 实现: 每个 Probe 返回 DiagnosticResult, 而不是 dict.
# 双轨运行: _run_module_with_timeout 优先查 _V2_PROBES, 存在走 Probe,
#           不存在走 GatewayTester 等旧类. 阶段 B13 再删除旧类.
#
# 设计要点:
#   1. Probe 不依赖现有 Tester 类 (避免双重 ping)
#   2. Probe 内部直接调 ping_host / get_default_gateway / THRESHOLDS 等工具
#   3. Probe 返回 DiagnosticResult; run_diagnostics 把 .metrics 字段填到
#      results[k], 兼容现有 verdict_fn / metrics_fn / _print_result / 报告渲染
#   4. issues 用 dataclass Issue (替代 dict), status 用 Status 枚举
#   5. Evidence 字段填充关键数据, 阶段 C 根因引擎可直接消费

_V2_PROBES = {}       # key -> probe_fn(callback=..., **kwargs) -> DiagnosticResult


def _register_probe(key):
    """装饰器: 把 probe_fn 注册到 _V2_PROBES (B7+ 阶段使用)."""
    def deco(fn):
        _V2_PROBES[key] = fn
        return fn
    return deco


@_register_probe("gateway")
def probe_gateway_v2(count=20, callback=None):
    """B7 gateway 探测 Probe 契约实现.

    与 GatewayTester.detect() 并行验证 (双轨), 输出零差异后 B13 删除旧实现.
    返回 DiagnosticResult, .metrics 字段保留 ping 结果供现有 verdict_fn /
    metrics_fn / _print_result / 报告渲染继续使用 (向后兼容).
    """
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()

    if callback:
        callback("正在检测网关延迟...")
    gateway = get_default_gateway()
    if not gateway:
        return DiagnosticResult(
            module_id="gateway", status=Status.ERROR,
            started_at=started_at,
            duration_ms=int((time.monotonic() - started_mono) * 1000),
            error=DiagnosticError(
                code="NO_GATEWAY", category="network",
                message="无法获取默认网关", retryable=True,
                severity=Severity.HIGH),
        )

    if callback:
        callback(f"Ping 网关 {gateway} ({count} 次)...")

    # wait_ms=3000 与系统默认接近, 避免 2.4G WiFi 偶发 >1.5s 响应被误判丢包
    ping_result = ping_host(gateway, count=count, timeout=count + 15, wait_ms=3000)

    avg = ping_result["avg_ms"]
    loss = ping_result["loss_pct"]
    jitter = ping_result.get("jitter_ms", 0)
    ttl = ping_result.get("ttl")

    # --- assessment (与 GatewayTester 完全一致) ---
    if loss > 5 and avg > 10:
        assessment = "网络质量差"
    elif loss > 5:
        assessment = "丢包严重"
    elif loss > 0:
        assessment = "存在丢包"
    elif avg > 100:
        assessment = "延迟严重"
    elif avg > 50:
        assessment = "延迟偏高"
    elif avg > 10:
        assessment = "延迟略高"
    else:
        assessment = "正常"

    # --- issues 转 dataclass Issue ---
    issues = []
    if avg >= 30:
        issues.append(Issue(
            id="gateway.high_latency", severity=Severity.CRITICAL,
            title=f"网关平均延迟 {avg}ms 超过阈值 30ms",
            description="网页加载变慢、视频会议可能卡顿、在线游戏高延迟",
            confidence=0.95,
            recommendations=[
                "① 检查网线是否松动",
                "② 查看 WiFi 信号强度 (<-65dBm 为弱)",
                "③ 登录路由器后台查看 CPU 占用率",
                "④ 如仍未改善请联系运营商",
            ],
        ))
    elif avg >= 10:
        issues.append(Issue(
            id="gateway.latency_high", severity=Severity.MEDIUM,
            title=f"网关平均延迟 {avg}ms 略高 (阈值 10ms)",
            description="对一般上网无明显影响, 实时游戏可能有轻微延迟",
            confidence=0.9,
            recommendations=["如果频繁出现卡顿, 可检查网线质量或考虑 5GHz WiFi"],
        ))
    if loss >= 5:
        issues.append(Issue(
            id="gateway.packet_loss", severity=Severity.CRITICAL,
            title=f"网关丢包 {loss}%",
            description="丢包会直接导致网页加载失败、视频卡顿",
            confidence=0.95,
            recommendations=["检查网线/WiFi 信号; 排除路由器/交换机过载"],
        ))
    elif loss >= 1:
        issues.append(Issue(
            id="gateway.packet_loss", severity=Severity.MEDIUM,
            title=f"网关丢包 {loss}%",
            description="丢包会直接导致网页加载失败、视频卡顿",
            confidence=0.9,
            recommendations=["检查网线/WiFi 信号; 排除路由器/交换机过载"],
        ))
    if jitter >= 50:
        issues.append(Issue(
            id="gateway.jitter", severity=Severity.CRITICAL,
            title=f"网关抖动 {jitter}ms 超过阈值 20ms",
            description="视频会议卡顿、VoIP 通话断续、在线游戏跳ping",
            confidence=0.9,
            recommendations=["优先排查 WiFi 信号/网线质量; 路由器 QoS 设置可能也有影响"],
        ))
    elif jitter >= 20:
        issues.append(Issue(
            id="gateway.jitter", severity=Severity.MEDIUM,
            title=f"网关抖动 {jitter}ms 超过阈值 20ms",
            description="视频会议卡顿、VoIP 通话断续、在线游戏跳ping",
            confidence=0.9,
            recommendations=["优先排查 WiFi 信号/网线质量; 路由器 QoS 设置可能也有影响"],
        ))

    # --- Status 推导 (与 GatewayTester.determine_status 行为一致) ---
    if any(i.severity == Severity.CRITICAL for i in issues):
        diag_status = Status.ERROR
    elif issues:
        diag_status = Status.WARNING
    else:
        diag_status = Status.OK

    # --- Evidence (阶段 C 根因引擎消费) ---
    evidence = [
        Evidence(id="gateway.ping.avg_ms", source="gateway.ping",
                 metric="avg_latency_ms", value=avg, unit="ms",
                 confidence=0.95, timestamp=started_at),
        Evidence(id="gateway.ping.loss_pct", source="gateway.ping",
                 metric="packet_loss_pct", value=loss, unit="%",
                 confidence=0.98, timestamp=started_at,
                 metadata={"sent": ping_result.get("sent"),
                           "received": ping_result.get("received")}),
        Evidence(id="gateway.ping.jitter_ms", source="gateway.ping",
                 metric="jitter_ms", value=jitter, unit="ms",
                 confidence=0.9, timestamp=started_at),
    ]
    if ttl is not None:
        evidence.append(Evidence(id="gateway.ping.ttl", source="gateway.ping",
                                 metric="ttl", value=ttl, confidence=0.85,
                                 timestamp=started_at))

    # --- metrics 字段: 兼容 GatewayTester.results 格式, 现有 verdict_fn /
    # metrics_fn / 报告渲染全部继续用 .metrics["ping"] / .metrics["issues"] 等 ---
    _avg0 = ping_result['avg_ms']
    _avg_txt = "<1" if (_avg0 < 1 and ping_result.get("rtts")) else f"{_avg0:g}"
    summary_text = (f"网关 {gateway}: 平均 {_avg_txt}ms, "
                    f"丢包 {ping_result['loss_pct']}%, 抖动 {ping_result['jitter_ms']}ms")
    metrics = {
        "gateway": gateway,
        "ping": ping_result,
        "assessment": assessment,
        "issues": [
            {
                "type": i.id,
                "severity": "critical" if i.severity == Severity.CRITICAL else "warning",
                "message": i.title,
                "detail": i.description,
                "action": "\n".join(i.recommendations) if i.recommendations else "",
            }
            for i in issues
        ],
        "timestamp": started_at,
        "summary": summary_text,
    }

    return DiagnosticResult(
        module_id="gateway", status=diag_status,
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        metrics=metrics, evidence=evidence, issues=issues,
    )


# ────────────────────────────────────────────────────────────────────────────
# B8-B11 通用 helper: Tester.results dict → DiagnosticResult
# ────────────────────────────────────────────────────────────────────────────
# 与 gateway probe 不同, dns/route/arp/wifi 模块逻辑复杂 (DNS 多服务器并行 /
# WiFi 信道分析 / ARP 重复去重), 完全重写探测逻辑工作量大且风险高.
# 务实方案: 调 Tester.detect() 拿 results dict, 再用 helper 包装为
# DiagnosticResult. _run_module_with_timeout 走 v2 路径时不会重复跑 detect()
# (旧 Tester.detect 路径已被覆盖), 因此无双重探测成本.

_SEVERITY_FROM_ZH = {
    "critical": Severity.CRITICAL, "error": Severity.CRITICAL,
    "warning": Severity.MEDIUM, "warn": Severity.MEDIUM,
    "info": Severity.LOW, "low": Severity.LOW,
}


# 模块错误文案 → 语义化错误码 (审计 P1-01): wrapper 不再把所有错误统一成
# MODULE_ERROR/retryable=True。顺序敏感, 先匹配更具体的特征 (中英都认,
# 兼容 box["err"] 回填的原始异常文本)。
_ERROR_PATTERNS = [
    # (特征子串小写, code, category, retryable, severity, exception_type)
    ("超时", "TIMEOUT", "timeout", True, Severity.MEDIUM, "TimeoutError"),
    ("timed out", "TIMEOUT", "timeout", True, Severity.MEDIUM, "TimeoutError"),
    ("timeout", "TIMEOUT", "timeout", True, Severity.MEDIUM, "TimeoutError"),
    ("权限", "PERMISSION_DENIED", "permission", False, Severity.HIGH, "PermissionError"),
    ("管理员", "PERMISSION_DENIED", "permission", False, Severity.HIGH, "PermissionError"),
    ("access is denied", "PERMISSION_DENIED", "permission", False, Severity.HIGH, "PermissionError"),
    ("permission", "PERMISSION_DENIED", "permission", False, Severity.HIGH, "PermissionError"),
    ("未找到", "UNAVAILABLE", "dependency", False, Severity.MEDIUM, "FileNotFoundError"),
    ("未安装", "UNAVAILABLE", "dependency", False, Severity.MEDIUM, "FileNotFoundError"),
    # v1.9.2 (审查修复): "无法获取网关地址" 是链路状态错误 (插回网线重测即恢复),
    # 不是缺依赖 — 归 NETWORK_ERROR 可重试, 不再误标 UNAVAILABLE/retryable=False
    ("无法获取", "NETWORK_ERROR", "network", True, Severity.MEDIUM, "ConnectionError"),
    ("not found", "UNAVAILABLE", "dependency", False, Severity.MEDIUM, "FileNotFoundError"),
    ("no such", "UNAVAILABLE", "dependency", False, Severity.MEDIUM, "FileNotFoundError"),
    ("连接失败", "NETWORK_ERROR", "network", True, Severity.MEDIUM, "ConnectionError"),
    ("unreachable", "NETWORK_ERROR", "network", True, Severity.MEDIUM, "ConnectionError"),
]


def _classify_module_error(message):
    """错误文案 → (code, category, retryable, severity, exception_type)。

    无特征命中时按 COMMAND_FAILED 兜底 (可重试, 与旧行为一致)。"""
    msg = str(message).lower()
    for pat, code, category, retryable, severity, exc in _ERROR_PATTERNS:
        if pat in msg:
            return code, category, retryable, severity, exc
    return "COMMAND_FAILED", "command", True, Severity.MEDIUM, "RuntimeError"


# ────────────────────────────────────────────────────────────────────────────
# P0-03 第一批 Evidence builders (v1.8.2): 旧 Tester.results → 结构化 Evidence。
# 原则: 只记录根因规则 (_rule_*) 实际读取的字段, 数值照抄 results dict 不做
# 二次加工; 模块 error / 数据缺失 → 空列表 (证据缺失 ≠ 证据为 0)。
# gateway 已是原生 probe (probe_gateway_v2 自建 Evidence), 不走此层。
# ────────────────────────────────────────────────────────────────────────────


def _ev_item(module, step, metric, value, unit=None, confidence=1.0, **metadata):
    """Evidence 快捷构造 (id 惯例: <module>.<step>.<metric>)."""
    return Evidence(id=f"{module}.{step}.{metric}", source=module, metric=metric,
                    value=value, unit=unit, confidence=confidence,
                    metadata=metadata)


def _evidence_external(res):
    """external: wan_interruption 规则同源字段 (tcp_ok/tcp_total/不可达数) + ping."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    out = []
    tcp_total = res.get("tcp_total")
    if tcp_total:
        out.append(_ev_item("external", "tcp", "tcp_ok", res.get("tcp_ok"),
                            confidence=0.98, tcp_total=tcp_total))
        out.append(_ev_item("external", "tcp", "unreachable_count",
                            res.get("unreachable_count", 0), confidence=0.98))
    if res.get("avg_loss_pct") is not None:
        out.append(_ev_item("external", "ping", "avg_loss_pct",
                            res["avg_loss_pct"], "%", 0.9))
    if res.get("avg_rtt_ms") is not None:
        out.append(_ev_item("external", "ping", "avg_rtt_ms",
                            res["avg_rtt_ms"], "ms", 0.9))
    return out


def _evidence_dns(res):
    """dns: dns_failure 规则同源字段 (success_count/total_count)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    total = res.get("total_count")
    if not total:
        return []
    return [_ev_item("dns", "resolve", "success_count", res.get("success_count"),
                     confidence=0.95, total_count=total)]


def _evidence_wifi(res):
    """wifi: wifi_weak 规则同源字段 (overall_interference)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    interference = res.get("overall_interference")
    if interference is None:
        return []
    return [_ev_item("wifi", "spectrum", "overall_interference", interference,
                     confidence=0.9)]


def _evidence_tcpstats(res):
    """tcpstats: tcp_loss_burst 规则同源字段 (retrans_rate_pct + 分子分母)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    rate = res.get("retrans_rate_pct")
    if not isinstance(rate, (int, float)):
        return []
    return [_ev_item("tcpstats", "retrans", "retrans_rate_pct", rate, "%", 0.9,
                     segments_sent=res.get("segments_sent"),
                     retransmitted=res.get("retransmitted"))]


def _evidence_mtu(res):
    """mtu: mtu_blackhole 规则同源字段 (path_mtus[].path_mtu + local_mtus[].mtu)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    out = []
    for r in res.get("path_mtus") or []:
        if r.get("error") or not r.get("path_mtu"):
            continue
        out.append(_ev_item("mtu", "probe", "path_mtu", r["path_mtu"], "B", 0.95,
                            target=r.get("target", "")))
    for lm in _clean_local_mtus(res.get("local_mtus")):
        # 键名以生产者 MTUDetector 为准: local_mtus[].interface (v1.9.2 修正)
        out.append(_ev_item("mtu", "iface", "mtu", lm["mtu"], "B", 0.95,
                            interface=lm.get("interface", "")))
    return out


def _evidence_web(res):
    """web: L7 分层耗时 (无根因规则, 供报告/排障追溯)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    out = []
    total = res.get("total_count")
    if total:
        out.append(_ev_item("web", "http", "ok_count", res.get("ok_count", 0),
                            confidence=0.95, total_count=total))
    for metric, step, unit in (("avg_ttfb_ms", "timing", "ms"),
                               ("avg_dns_ms", "dns", "ms"),
                               ("avg_tls_ms", "tls", "ms"),
                               ("min_cert_days", "cert", "天")):
        v = res.get(metric)
        if v is not None:
            out.append(_ev_item("web", step, metric, v, unit, 0.9))
    return out


def _evidence_bufferbloat(res):
    """bufferbloat: 规则同源字段 (bloat_ms + grade + load_warning 有效性标志)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    out = []
    idle, loaded = res.get("idle_rtt_ms"), res.get("loaded_rtt_ms")
    if isinstance(idle, (int, float)) and isinstance(loaded, (int, float)):
        bloat = res.get("bloat_ms")
        if not isinstance(bloat, (int, float)):
            bloat = loaded - idle
        out.append(_ev_item("bufferbloat", "load", "bloat_ms", bloat, "ms", 0.9,
                            idle_rtt_ms=idle, loaded_rtt_ms=loaded))
    if res.get("grade"):
        out.append(_ev_item("bufferbloat", "grade", "grade", res["grade"],
                            confidence=0.9))
    if res.get("load_warning") is not None:
        out.append(_ev_item("bufferbloat", "load", "load_warning",
                            bool(res["load_warning"]), confidence=0.95))
    return out


def _evidence_nattype(res):
    """nattype: nat_restricted 规则同源字段 (nat_behavior + cone_type)."""
    if not isinstance(res, dict) or res.get("error"):
        return []
    out = []
    if res.get("nat_behavior"):
        out.append(_ev_item("nattype", "stun", "nat_behavior",
                            res["nat_behavior"], confidence=0.9))
    if res.get("cone_type"):
        out.append(_ev_item("nattype", "stun", "cone_type",
                            res["cone_type"], confidence=0.85))
    return out


def _wrap_as_diagnostic_result(results, module_id, started_at, duration_ms,
                               evidence_fn=None):
    """通用: Tester.results dict → DiagnosticResult (B8-B11 共享 helper).

    复用 determine_status() 推中文状态 → Status 枚举, 不破坏现有 verdict_fn /
    metrics_fn / _print_result / 报告渲染的语义.
    metrics 字段完整保留旧 results dict (兼容 _verdict_xxx / _metrics_xxx).
    evidence_fn: (results) -> list[Evidence] (P0-03 迁移期, v1.8.2)。
                 生成抛异常只丢弃证据, 不阻断主结果。
    """
    if not results:
        # v1.9.2 (审查修复): 空 results 旧路径映射 determine_status({})="未检测",
        # wrapper 此前给 UNKNOWN("未知") — 不在 schema 状态枚举里且不计入健康分
        return DiagnosticResult(
            module_id=module_id, status=Status.IDLE,
            started_at=started_at, duration_ms=duration_ms)

    status_zh = determine_status(results)
    diag_status = Status.from_zh(status_zh)

    error = None
    if "error" in results:
        code, category, retryable, severity, exc_type = _classify_module_error(
            results["error"])
        error = DiagnosticError(
            code=code, category=category,
            message=str(results["error"]),
            retryable=retryable, severity=severity,
            exception_type=exc_type)
        # 模块级 error 标志: 若 determine_status 未升级到 ERROR, 这里强制升级
        if diag_status == Status.OK:
            diag_status = Status.ERROR

    issues = []
    for i in results.get("issues") or []:
        if not isinstance(i, dict):
            continue
        sev_str = str(i.get("severity", "warning")).lower()
        severity = _SEVERITY_FROM_ZH.get(sev_str, Severity.MEDIUM)
        action = i.get("action", "")
        if isinstance(action, str) and action:
            recommendations = [action]
        else:
            recommendations = []
        issues.append(Issue(
            id=str(i.get("type", "issue")),
            severity=severity,
            title=str(i.get("message", str(i))),
            description=str(i.get("detail", "")),
            # confidence 不填 (None): 旧结果没有真实置信度依据 (审计 P1-02)
            recommendations=recommendations,
        ))

    evidence = []
    if evidence_fn is not None:
        try:
            evidence = [e for e in (evidence_fn(results) or [])
                        if isinstance(e, Evidence)]
        except Exception:
            evidence = []      # 证据生成失败不阻断主结果
    return DiagnosticResult(
        module_id=module_id, status=diag_status,
        started_at=started_at, duration_ms=duration_ms,
        metrics=results,      # 完整保留旧 dict, 供 verdict_fn / 报告渲染
        evidence=evidence, issues=issues, error=error)


# ────────────────────────────────────────────────────────────────────────────
# B8 dns · B9 route · B10 arp · B11 wifi — 模块契约 probe 实现
# ────────────────────────────────────────────────────────────────────────────


@_register_probe("dns")
def probe_dns_v2(callback=None):
    """B8 DNS 诊断 Probe 契约. 调用 DNSTester.detect() + wrap helper (P0-03 接入证据)."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = DNSTester()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="dns",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_dns)


@_register_probe("route")
def probe_route_v2(callback=None):
    """B9 路由表分析 Probe 契约. 调用 RouteTableAnalyzer.detect() + wrap helper."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = RouteTableAnalyzer()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="route",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000))


@_register_probe("arp")
def probe_arp_v2(callback=None):
    """B10 ARP 表分析 Probe 契约. 调用 ARPAnalyzer.detect() + wrap helper."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = ARPAnalyzer()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="arp",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000))


@_register_probe("wifi")
def probe_wifi_v2(callback=None):
    """B11 WiFi 干扰分析 Probe 契约. 调用 WiFiAnalyzer.detect() + wrap helper (P0-03 接入证据)."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = WiFiAnalyzer()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="wifi",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_wifi)


# ── P0-03 第一批迁移 (v1.8.2): external / tcpstats / mtu / web 进入 V2 双轨 ──
# 模式与 B8-B11 相同: Tester.detect() → wrap helper + 模块专属 Evidence builder。
# 状态/指标口径与旧 Tester 路径零差异 (同一 determine_status, metrics 全保留)。


@_register_probe("external")
def probe_external_v2(callback=None):
    """外网检测 Probe (P0-03 第一批). ExternalNetworkTester + 原生 Evidence."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = ExternalNetworkTester()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="external",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_external)


@_register_probe("tcpstats")
def probe_tcpstats_v2(callback=None):
    """TCP 传输质量 Probe (P0-03 第一批). TCPStatsTester + 原生 Evidence."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = TCPStatsTester()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="tcpstats",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_tcpstats)


@_register_probe("mtu")
def probe_mtu_v2(callback=None):
    """MTU 检测 Probe (P0-03 第一批). MTUDetector + 原生 Evidence."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = MTUDetector()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="mtu",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_mtu)


@_register_probe("web")
def probe_web_v2(callback=None):
    """网页体检 Probe (P0-03 第一批). WebPageTester + 原生 Evidence.

    detect 参数统一走 _module_detect_kwargs — 与旧路径严格同源, 不手工拷贝。"""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = WebPageTester()
    t.detect(callback=callback, **_module_detect_kwargs("web"))
    return _wrap_as_diagnostic_result(
        t.results, module_id="web",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_web)


@_register_probe("bufferbloat")
def probe_bufferbloat_v2(callback=None):
    """Bufferbloat Probe (P0-03 第二批). BufferbloatTester + 原生 Evidence."""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = BufferbloatTester()
    t.detect(callback=callback)
    return _wrap_as_diagnostic_result(
        t.results, module_id="bufferbloat",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_bufferbloat)


@_register_probe("nattype")
def probe_nattype_v2(callback=None):
    """NAT 类型 Probe (P0-03 第二批). NATTypeTester + 原生 Evidence.

    detect 参数统一走 _module_detect_kwargs — 与旧路径严格同源, 不手工拷贝。"""
    started_mono = time.monotonic()
    started_at = datetime.now().isoformat()
    t = NATTypeTester()
    t.detect(callback=callback, **_module_detect_kwargs("nattype"))
    return _wrap_as_diagnostic_result(
        t.results, module_id="nattype",
        started_at=started_at,
        duration_ms=int((time.monotonic() - started_mono) * 1000),
        evidence_fn=_evidence_nattype)


# ============================================================
# SECTION 1f: DIAGNOSIS  (阶段 C · v1.3.0 引入)
# ============================================================
# 根因分析引擎: 把"23 项独立检测"升级为"故障定位"。
# 输入: run_diagnostics 输出的 full dict ({key: results_dict})
# 输出: DiagnosisReport (list[RootCause] + overall_confidence)
#
# 设计要点:
#   1. 规则 = 纯函数 (results_dict) → RootCause | None
#   2. 每条规则可独立测试, 不依赖其他规则
#   3. RootCause 引用 evidence IDs (B 阶段 DiagnosticResult.evidence 字段)
#   4. confidence 基于: evidence 数量 × 模块 status × 阈值偏差
#   5. 同根因多个证据合并, 避免"同一根因重复扣分"
#
# 6 条内置规则:
#   _rule_dns_failure      DNS 解析异常 (gateway OK + DNS fail > 50%)
#   _rule_wan_interruption WAN 中断    (gateway OK + external ping/TCP 全失败)
#   _rule_wifi_weak        WiFi 干扰   (WiFi 干扰等级 >= 较高)
#   _rule_bufferbloat      Bufferbloat (loaded_latency 远大于 idle_latency)
#   _rule_gateway_loss     网关丢包    (gateway loss >= 5%)
#   _rule_nat_restricted   NAT 限制    (STUN 测得 Symmetric NAT)

@dataclass
class RootCause:
    """根因: 跨模块证据聚合出的故障定位.

    与 Issue 区别: Issue 是单模块内部问题 (e.g. gateway.high_latency),
    RootCause 是跨模块聚合 (e.g. "DNS 故障" 关联 gateway OK + external OK + dns fail).
    """
    id: str                                # "dns_failure"
    category: str                          # "DNS" / "WAN" / "WiFi" / "Bufferbloat" / "LAN" / "NAT"
    severity: Severity
    title: str                             # "DNS 解析异常"
    description: str                       # 影响范围说明
    confidence: float = 0.0                # 0.0-1.0
    evidence_ids: list[str] = field(default_factory=list)    # 引用的 evidence IDs (B 阶段字段)
    affected_modules: list[str] = field(default_factory=list) # 涉及哪些模块 key
    recommendations: list[str] = field(default_factory=list)  # 建议清单
    # v1.5.0 证据链: 供报告渲染「为什么这样判断 / 已排除什么」
    # 每项 {"text": str, "ok": bool}; supports 里 ok=False 表示"问题就在这",
    # excludes 全部 ok=True。由 _enrich_diagnosis_evidence 填充。
    supports: list[dict] = field(default_factory=list)
    excludes: list[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.id, "category": self.category,
            "severity": self.severity.value,
            "title": self.title, "description": self.description,
            "confidence": round(self.confidence, 3),
            "evidence_ids": list(self.evidence_ids),
            "affected_modules": list(self.affected_modules),
            "recommendations": list(self.recommendations),
            "supports": [dict(s) for s in self.supports],
            "excludes": [dict(e) for e in self.excludes],
        }


@dataclass
class DiagnosisReport:
    """根因分析报告: 一次完整诊断的所有根因."""
    root_causes: list[RootCause] = field(default_factory=list)
    overall_confidence: float = 0.0       # 多根因加权平均
    timestamp: str = ""
    rules_evaluated: int = 0               # 评估的规则数
    rules_fired: int = 0                   # 触发的规则数

    def to_dict(self):
        return {
            "root_causes": [rc.to_dict() for rc in self.root_causes],
            "overall_confidence": round(self.overall_confidence, 3),
            "timestamp": self.timestamp,
            "rules_evaluated": self.rules_evaluated,
            "rules_fired": self.rules_fired,
        }


# ────────────────────────────────────────────────────────────────────────────
# confidence 加权算法 (C2)
# ────────────────────────────────────────────────────────────────────────────
# 设计: confidence = 模块可信度 × 证据强度 × 阈值偏差
#   - 模块可信度: 模块 status 是 OK/WARNING/ERROR 的基础可信度 (1.0/0.7/0.95)
#   - 证据强度: evidence 数量 / 期望数量 (0.0-1.0)
#   - 阈值偏差: 实际值偏离阈值的程度 (0.0-1.0, 偏差越大越确信是问题)
# 最终 confidence = 加权平均, 钳到 [0.0, 1.0]


def _module_status_confidence(results):
    """模块 status 基础可信度: ERROR=0.95 (高), WARNING=0.7, OK=0.4 (低)."""
    if not results:
        return 0.0
    err = results.get("error")
    if err:
        return 0.0
    issues = results.get("issues") or []
    if any(isinstance(i, dict) and i.get("severity") == "critical" for i in issues):
        return 0.95
    if any(isinstance(i, dict) and i.get("severity") == "warning" for i in issues):
        return 0.7
    return 0.4


def _rule_confidence(modules, base=0.5):
    """综合多个模块的置信度.

    modules: list of (results_dict, weight) tuples
    返回: 0.0-1.0 加权平均
    """
    if not modules:
        return 0.0
    total_w = 0.0
    weighted = 0.0
    for results, weight in modules:
        c = _module_status_confidence(results)
        weighted += c * weight
        total_w += weight
    if total_w == 0:
        return 0.0
    # 钳到 [base, 1.0], 避免永远 0.4
    return max(base, min(1.0, weighted / total_w))


# ────────────────────────────────────────────────────────────────────────────
# 6 条内置规则 (C1)
# ────────────────────────────────────────────────────────────────────────────

def _rule_dns_failure(results_dict):
    """DNS 故障: gateway OK + DNS 解析失败率 > 50%."""
    dns_res = results_dict.get("dns", {})
    if not dns_res:
        return None
    if dns_res.get("error"):
        # 模块自身崩溃/超时 → DNS 从未被测试, 工具故障不是网络根因
        return None
    # DNS 失败率: success_count / total_count (键名与 DNSTester.results 一致)
    sc = dns_res.get("success_count", 0)
    tc = dns_res.get("total_count", 0) or 1
    fail_rate = 1 - (sc / tc) if tc > 0 else 0
    if fail_rate <= 0.5:
        return None
    # gateway 必须可达 (排除 WAN 全断)
    gw = results_dict.get("gateway", {})
    gw_ok = not gw.get("error") and (gw.get("ping", {}).get("loss_pct", 100) < 50)
    if not gw_ok:
        return None  # 网关都不可达, 不归 DNS
    confidence = _rule_confidence([(dns_res, 1.0), (gw, 0.3)], base=0.7)
    return RootCause(
        id="dns_failure", category="DNS", severity=Severity.HIGH,
        title=f"DNS 解析异常 (失败率 {fail_rate*100:.0f}%)",
        description="公网域名解析失败, 网页/应用可能无法访问; 网关和外网均可达, 故障点在 DNS.",
        confidence=confidence,
        evidence_ids=["dns.success_count", "dns.total_count", "gateway.ping.loss_pct"],
        affected_modules=["dns", "gateway"],
        recommendations=[
            "1. 换 DNS 服务器 (推荐 223.5.5.5 / 119.29.29.29 / 114.114.114.114)",
            "2. 检查路由器 DNS 转发配置",
            "3. 排除安全软件 / 代理的 DNS 劫持",
            "4. 若仅系统 DNS 异常, 系统设置里手动指定公共 DNS",
        ],
    )


def _rule_wan_interruption(results_dict):
    """WAN 中断: gateway OK + external TCP 全失败."""
    ext_res = results_dict.get("external", {})
    gw = results_dict.get("gateway", {})
    if not ext_res or not gw:
        return None
    if ext_res.get("error"):
        # 模块自身崩溃/超时 → 外网从未被测试, 不能当 WAN 中断的证据
        return None
    gw_ok = not gw.get("error") and (gw.get("ping", {}).get("loss_pct", 100) < 50)
    if not gw_ok:
        return None  # 网关不通, 不归 WAN
    # ExternalNetworkTester.results 的键: tcp_ok / tcp_total / unreachable_count
    tcp_total = ext_res.get("tcp_total", 0) or 0
    tcp_ok = ext_res.get("tcp_ok", 0) or 0
    if tcp_total <= 0 or tcp_ok > 0:
        return None  # 至少一个目标 TCP 可达 / 无目标数据, 不算 WAN 中断
    confidence = _rule_confidence([(ext_res, 1.0), (gw, 0.3)], base=0.7)
    return RootCause(
        id="wan_interruption", category="WAN", severity=Severity.CRITICAL,
        title="WAN 中断 (运营商链路故障)",
        description="网关可达但外网不可达, 故障点在『网关 ↔ 运营商』这一段; 需联系运营商.",
        confidence=confidence,
        evidence_ids=["external.tcp_ok", "external.tcp_total", "gateway.ping.loss_pct"],
        affected_modules=["external", "gateway"],
        recommendations=[
            "1. 检查光猫 LOS 灯是否变红 (光纤断)",
            "2. 重启光猫+路由器",
            "3. 联系运营商客服报修",
        ],
    )


def _rule_wifi_weak(results_dict):
    """WiFi 干扰: WiFi 干扰等级 >= 较高."""
    wifi = results_dict.get("wifi", {})
    if not wifi:
        return None
    interference = wifi.get("overall_interference", "正常")
    if "干扰" not in interference or interference == "正常":
        return None
    if interference not in ("干扰较高", "严重干扰"):
        return None
    confidence = _rule_confidence([(wifi, 1.0)], base=0.7)
    severity = Severity.CRITICAL if "严重" in interference else Severity.HIGH
    return RootCause(
        id="wifi_weak", category="WiFi", severity=severity,
        title=f"WiFi 信道{interference}",
        description="WiFi 速率下降/延迟增加/设备连接不稳定; 干扰等级越高, 表现越明显.",
        confidence=confidence,
        evidence_ids=["wifi.overall_interference", "wifi.channel_analysis"],
        affected_modules=["wifi"],
        recommendations=[
            "1. 路由器后台切换到推荐信道 (见报告『建议信道』)",
            "2. 优先使用 5GHz 频段 (穿墙弱但干扰少)",
            "3. 路由器放房屋中心位置, 远离微波炉/蓝牙设备",
        ],
    )


def _rule_bufferbloat(results_dict):
    """Bufferbloat: loaded_rtt / idle_rtt 比值过大."""
    bb = results_dict.get("bufferbloat", {})
    if not bb or bb.get("error"):
        return None
    if bb.get("load_warning"):
        return None  # 测速源不可用, 负载未建立, 结果不可信
    idle = bb.get("idle_rtt_ms")
    loaded = bb.get("loaded_rtt_ms")
    if idle is None or loaded is None:
        return None
    bloat = bb.get("bloat_ms")
    if bloat is None:
        bloat = loaded - idle
    # BufferbloatTester 的 grade 是带说明的中文串, 取首字母判定档位
    grade = bb.get("grade", "") or ""
    grade_letter = grade[:1].upper()
    if grade_letter not in ("D", "F") and (idle <= 0 or loaded < idle * 3):
        return None
    confidence = _rule_confidence([(bb, 1.0)], base=0.7)
    severity = Severity.CRITICAL if grade_letter == "F" else Severity.HIGH
    return RootCause(
        id="bufferbloat", category="Bufferbloat", severity=severity,
        title=f"Bufferbloat 严重 (等级 {grade}, 延迟增加 {bloat:.0f}ms)",
        description="网络空闲时延迟正常, 加载下载时延迟飙升; 是上游带宽/路由器缓存调优差.",
        confidence=confidence,
        evidence_ids=["bufferbloat.grade", "bufferbloat.loaded_rtt_ms",
                       "bufferbloat.idle_rtt_ms", "bufferbloat.bloat_ms"],
        affected_modules=["bufferbloat"],
        recommendations=[
            "1. 登录路由器后台开启 SQM / QoS (智能队列管理)",
            "2. 联系运营商确认上联带宽是否过度订阅",
            "3. 考虑更换为支持 fq_codel / CAKE 的路由器固件",
        ],
    )


def _rule_gateway_loss(results_dict):
    """网关丢包: gateway loss >= 5%."""
    gw = results_dict.get("gateway", {})
    if not gw or gw.get("error"):
        return None
    ping = gw.get("ping", {})
    loss = ping.get("loss_pct", 0)
    if loss < 5:
        return None
    confidence = _rule_confidence([(gw, 1.0)], base=0.7)
    severity = Severity.CRITICAL if loss >= 20 else Severity.HIGH
    return RootCause(
        id="gateway_loss", category="LAN", severity=severity,
        title=f"网关丢包 {loss}%",
        description="『本机 ↔ 网关』链路有丢包; 故障点在网线/WiFi/路由器, 与运营商无关.",
        confidence=confidence,
        evidence_ids=["gateway.ping.loss_pct", "gateway.ping.avg_ms"],
        affected_modules=["gateway"],
        recommendations=[
            "1. 检查网线是否松动/破损 (更换 Cat5e 以上网线)",
            "2. WiFi 连接时: 检查信号强度 (<-65dBm 为弱)",
            "3. 路由器后台查看 CPU/内存占用 (过载会丢包)",
            "4. 排除家用交换机/电力猫过载",
        ],
    )


def _rule_nat_restricted(results_dict):
    """NAT 限制: STUN 测得对称型 NAT (游戏/P2P 不友好)."""
    nat = results_dict.get("nattype", {})
    if not nat or nat.get("error"):
        return None
    # NATTypeTester.results 的键: nat_behavior ('对称型'/'EIM(锥形)'/未知) + cone_type
    behavior = nat.get("nat_behavior", "") or ""
    if "对称" not in behavior and "symmetric" not in behavior.lower():
        return None
    confidence = _rule_confidence([(nat, 0.8)], base=0.65)
    return RootCause(
        id="nat_restricted", category="NAT", severity=Severity.MEDIUM,
        title="运营商 NAT 类型受限 (对称型)",
        description="对称型 NAT 对游戏主机/视频通话/P2P 不友好, 直连建立困难; 影响游戏联机和 VoIP 质量.",
        confidence=confidence,
        evidence_ids=["nattype.nat_behavior", "nattype.cone_type"],
        affected_modules=["nattype"],
        recommendations=[
            "1. 路由器开启 UPnP (自动端口映射)",
            "2. 或手动为游戏主机配置端口转发 / DMZ 主机",
            "3. 极端情况: 联系运营商申请公网 IP (需企业级)",
        ],
    )


# ────────────────────────────────────────────────────────────────────────────
# 证据链生成 (v1.5.0)
# ────────────────────────────────────────────────────────────────────────────
# 背景: B 阶段引入的 Evidence 实体目前只在 gateway 模块实际构造 (全仓 4 处),
# 覆盖率极低, 因此 RootCause.evidence_ids **不能**直接渲染成"证据链" — 大多数
# id 找不到对应实体。这里改为按规则的判定条件反向生成人话证据:
#   supports — 支持本结论的事实 (ok=False: 问题就在这; ok=True: 佐证)
#   excludes — 已经排除的方向 (全部 ok=True)
# 约束: 只读取规则函数里已经验证过的字段名; 字段缺失就跳过该条, 不伪造数字。

# IPv4 MTU 有效区间: 68(最小) ~ 65535(理论最大)。Windows 回环口
# (Loopback Pseudo-Interface 1) 的 NlMtu 是 4294967295 (0xFFFFFFFF, -1 的
# 无符号形式), 属设计值, 不代表真实链路 MTU —— 若不剔除, 规则/证据会把
# "接口 4294967295" 当成本机最大 MTU, 伪判 MTU 黑洞并给出无意义的修复建议
# (v1.9.3 修复, 报告曾出现 "路径 1500 < 接口 4294967295, 差 4294965795")。
_MTU_VALID_MIN = 68
_MTU_VALID_MAX = 65535


def _clean_local_mtus(local_mtus):
    """过滤本地接口 MTU 列表中的无效项 (探测侧与规则侧共用, 双保险)。

    剔除: 数值非 [68, 65535] (覆盖回环口 4294967295 等)、接口名含
    "Loopback" 的项。返回保留原字段结构的 dict 列表; 空输入 → []。
    """
    out = []
    for lm in local_mtus or []:
        if not isinstance(lm, dict):
            continue
        try:
            v = int(lm.get("mtu") or 0)
        except (TypeError, ValueError):
            continue
        name = str(lm.get("interface") or lm.get("name") or "")
        if v < _MTU_VALID_MIN or v > _MTU_VALID_MAX:
            continue
        if "loopback" in name.lower():
            continue
        out.append(dict(lm))
    return out


def _rule_mtu_blackhole(results_dict):
    """MTU 黑洞 (v1.7.0 PR-F0): 路径 MTU 显著小于本机接口 MTU。

    PMTUD 黑洞类故障: 小包 (ping/握手) 正常, full-size 数据包被中间
    设备静默丢弃 — 视频卡顿/大文件慢的典型根因, L3 探测看不出。
    判据: 本机接口 MTU − 最小有效路径 MTU ≥ 100 (PPPoE 的 1492 不误报);
    tcpstats 重传率 ≥5% 佐证时置信度上调 (0.75 → 0.92)。
    """
    mtu = results_dict.get("mtu", {})
    if not mtu or mtu.get("error"):
        return None
    # MTUDetector.results 的键: path_mtus[].path_mtu / local_mtus[].mtu
    paths = [r.get("path_mtu") for r in (mtu.get("path_mtus") or [])
             if not r.get("error") and r.get("path_mtu")]
    local_items = _clean_local_mtus(mtu.get("local_mtus"))
    if not paths or not local_items:
        return None
    path_min = min(paths)
    # 对比对象应是"真实承载流量的出口接口", 不是全列表极值:
    # 回环口 4294967295 / 未承载路由的 VPN 虚拟口 (如 ZeroTier 2800) 若
    # 混入 max(), 会把正常链路伪判成 MTU 黑洞 (v1.9.3)。探测侧已标记
    # egress (默认路由出口), 此处优先取它; 标记缺失时退回清洗后最大值。
    eg = next((lm for lm in local_items if lm.get("egress")), None)
    if eg is not None:
        if_max, if_name = eg["mtu"], eg.get("interface") or ""
    else:
        if_max = max(lm["mtu"] for lm in local_items)
        if_name = next((lm.get("interface", "") or "" for lm in local_items
                        if lm["mtu"] == if_max), "")
    diff = if_max - path_min
    if diff < 100:
        return None
    ts = results_dict.get("tcpstats", {}) or {}
    retrans_rate = ts.get("retrans_rate_pct")
    corroborated = isinstance(retrans_rate, (int, float)) and retrans_rate >= 5
    confidence = 0.92 if corroborated else 0.75
    # 建议里的"接口名"程序已能拿到 (egress/最大 MTU 项), 直接填真实名字,
    # 不再让用户自己对着 netsh 帮助找接口名 (v1.9.3)。
    if_name_part = f"\"{if_name}\"" if if_name else "\"接口名\""
    return RootCause(
        id="mtu_blackhole", category="MTU", severity=Severity.HIGH,
        title=f"MTU 不匹配 (路径 {path_min} < 接口 {if_max}, 差 {diff})",
        description=("本机能发出的包大于通道实际能承载的 MTU, 大包被静默丢弃引发重传/卡顿; "
                     "ping 与握手是小包不受影响, 常规探测看不出."),
        confidence=confidence,
        evidence_ids=["mtu.path_mtus", "mtu.local_mtus", "tcpstats.retrans_rate_pct"],
        affected_modules=["mtu", "tcpstats"],
        recommendations=[
            f"1. 将电脑接口 {if_name or 'MTU'} 改为 {path_min}: netsh interface ipv4 set "
            f"subinterface {if_name_part} mtu={path_min} store=persistent (管理员), 改后复测",
            "2. 检查路由器/中间设备的 MSS clamping (典型配置 ip tcp adjust-mss)",
            "3. 物联网卡/专线场景联系运营商核对通道 MTU",
        ],
    )


def _rule_tcp_loss_burst(results_dict):
    """TCP 传输层丢包 (v1.7.0 PR-F0): 重传率超标。

    注意口径: tcpstats 是开机以来的累计计数器 — 偏高可能包含历史时段,
    建议盯障模式 (--monitor) 的会话差分口径复测确认后再报障。
    """
    ts = results_dict.get("tcpstats", {})
    if not ts or ts.get("error"):
        return None
    rate = ts.get("retrans_rate_pct")
    if not isinstance(rate, (int, float)) or rate < 5:
        return None          # 1%~5% 已在模块 issues 里提示, 不升根因
    return RootCause(
        id="tcp_loss_burst", category="WAN", severity=Severity.MEDIUM,
        title=f"TCP 重传率 {rate:g}% 偏高 (传输层丢包)",
        description=("TCP 层大量重传, 应用表现为视频卡顿/下载慢; "
                     "注意此为开机累计口径, 建议盯障复测确认是当前时段的问题."),
        confidence=0.70,
        evidence_ids=["tcpstats.retrans_rate_pct", "tcpstats.retransmitted",
                      "tcpstats.segments_sent"],
        affected_modules=["tcpstats"],
        recommendations=[
            "1. 复测确认口径: netpulse --monitor 600 (会话差分重传率, 报告含时序)",
            "2. 结合 MTU 检测结果区分: MTU 不匹配 → 改 MTU; 否则链路质量/拥塞",
            "3. MTU 正常仍高: 带报告向运营商报障 (查光衰/线路质量)",
        ],
    )


def _ev(text, ok):
    """构造一条证据项。"""
    return {"text": text, "ok": bool(ok)}


def _mod(results, key):
    """取模块原始结果 (不存在 / 出错 / 非 dict 时返回 None)。"""
    res = (results or {}).get(key)
    if not isinstance(res, dict) or not res or res.get("error"):
        return None
    return res


def _ping(results, key):
    """取模块的 ping 子结构。"""
    res = _mod(results, key)
    if not res:
        return None
    ping = res.get("ping")
    return ping if isinstance(ping, dict) else None


def _ev_gateway_reachable(results, evd=None, suffix=""):
    """通用的「网关可达」排除项 (v1.8.4: 优先取 gateway 自证 Evidence)。"""
    item = _evd_find(_module_evidence(evd, "gateway"),
                     "gateway.ping.loss_pct")
    ping = _ping(results, "gateway")
    if item is not None and isinstance(item.get("value"), (int, float)):
        loss = item["value"]
        i_avg = _evd_find(_module_evidence(evd, "gateway"),
                          "gateway.ping.avg_ms")
        avg = i_avg.get("value") if i_avg is not None else None
    elif ping:
        loss = ping.get("loss_pct", 0)
        avg = ping.get("avg_ms")
    else:
        return None
    if not isinstance(loss, (int, float)) or loss >= 50:
        return None
    txt = f"网关可达，丢包 {loss:g}%"
    if isinstance(avg, (int, float)):
        # 局域网 <1ms 时 ping 输出整数 0, 按 <1ms 表达避免"平均 0ms"误解
        txt += f"，平均 {'<1' if avg < 1 else f'{avg:g}'}ms"
    return _ev(txt + suffix, True)


def _ev_external_reachable(results, evd=None, suffix="（不是外网全断）"):
    """通用的「外网 TCP 可达」排除项 (v1.8.4: 优先取 external 自证 Evidence)。"""
    ext = _mod(results, "external")
    item = _evd_find(_module_evidence(evd, "external"),
                     "external.tcp.tcp_ok")
    if item is not None and (item.get("metadata") or {}).get("tcp_total"):
        tcp_ok = item.get("value") or 0
        tcp_total = item["metadata"]["tcp_total"]
    elif ext:
        tcp_ok, tcp_total = ext.get("tcp_ok", 0) or 0, ext.get("tcp_total", 0) or 0
    else:
        return None
    if not tcp_total or tcp_ok <= 0:
        return None
    return _ev(f"外网 TCP 可达 {tcp_ok}/{tcp_total}{suffix}", True)


def _module_evidence(evd, module):
    """模块自证 Evidence (v1.9.0 起来自独立映射 LAST_RUN["evidence"])。

    evd: {module_key: [Evidence.to_dict(), ...]}; None/缺失/损坏 → []。
    """
    ev = (evd or {}).get(module)
    return [e for e in ev if isinstance(e, dict)] if isinstance(ev, list) else []


def _evd_find(evidence, ev_id):
    """按 id 取第一条模块 Evidence; 无则 None。"""
    for e in evidence:
        if e.get("id") == ev_id:
            return e
    return None


def _ev_dns_failure(results, evd=None):
    dns = _mod(results, "dns") or {}
    supports = []
    # 支持项优先取模块自证 Evidence (v1.8.3, 与 probe 认证数值同源);
    # 旧运行/无证据时回落原地取值, 文案不变。
    item = _evd_find(_module_evidence(evd, "dns"),
                     "dns.resolve.success_count")
    meta = (item or {}).get("metadata") or {}
    if item is not None and isinstance(item.get("value"), (int, float)) \
            and meta.get("total_count"):
        sc, tc = item["value"], meta["total_count"]
    else:
        sc, tc = dns.get("success_count", 0) or 0, dns.get("total_count", 0) or 0
    if tc:
        supports.append(_ev(
            f"DNS 解析仅 {sc}/{tc} 成功，失败率 {(1 - sc / tc) * 100:.0f}%", False))
    excludes = []
    for fn in (_ev_gateway_reachable, _ev_external_reachable):
        item = fn(results, evd)     # v1.9.1: 透传证据映射 (审查修复)
        if item:
            excludes.append(item)
    if excludes:
        excludes.append(_ev("本机到网关这一段正常，问题不在网线 / 路由器内网侧", True))
    return supports, excludes


def _ev_wan_interruption(results, evd=None):
    ext = _mod(results, "external") or {}
    supports = []
    item = _evd_find(_module_evidence(evd, "external"),
                     "external.tcp.tcp_ok")
    meta = (item or {}).get("metadata") or {}
    if item is not None and meta.get("tcp_total"):
        tcp_ok, tcp_total = item.get("value") or 0, meta["tcp_total"]
    else:
        tcp_ok, tcp_total = ext.get("tcp_ok", 0) or 0, ext.get("tcp_total", 0) or 0
    if tcp_total:
        supports.append(_ev(f"外网 TCP 全部失败 {tcp_ok}/{tcp_total}", False))
    excludes = []
    item = _ev_gateway_reachable(results, evd, suffix="（内网到网关这一段没问题）")
    if item:
        excludes.append(item)
    i_loss = _evd_find(_module_evidence(evd, "gateway"),
                       "gateway.ping.loss_pct")
    if i_loss is not None and isinstance(i_loss.get("value"), (int, float)):
        gw_loss = i_loss["value"]
    else:
        ping = _ping(results, "gateway")
        gw_loss = ping.get("loss_pct") if ping else None
    if isinstance(gw_loss, (int, float)) and gw_loss < 5:
        excludes.append(_ev("本机网卡与网线 / WiFi 链路无丢包", True))
    return supports, excludes


def _ev_wifi_weak(results, evd=None):
    wifi = _mod(results, "wifi") or {}
    supports = []
    item = _evd_find(_module_evidence(evd, "wifi"),
                     "wifi.spectrum.overall_interference")
    if item is not None and item.get("value") is not None:
        interference = item.get("value")
    else:
        interference = wifi.get("overall_interference")
    if interference:
        supports.append(_ev(f"WiFi 干扰等级：{interference}", False))
    nets = wifi.get("networks")
    if isinstance(nets, list) and nets:
        supports.append(_ev(f"周边扫描到 {len(nets)} 个无线网络", True))
    excludes = []
    item = _ev_gateway_reachable(results, evd, suffix="（到网关的有线/链路层未受影响）")
    if item:
        excludes.append(item)
    item = _ev_external_reachable(results, evd, suffix="（运营商侧链路正常）")
    if item:
        excludes.append(item)
    return supports, excludes


def _ev_bufferbloat(results, evd=None):
    bb = _mod(results, "bufferbloat") or {}
    supports = []
    ev = _module_evidence(evd, "bufferbloat")
    item = _evd_find(ev, "bufferbloat.load.bloat_ms")
    if item is not None and isinstance(item.get("value"), (int, float)):
        meta = item.get("metadata") or {}
        idle, loaded = meta.get("idle_rtt_ms"), meta.get("loaded_rtt_ms")
        if isinstance(idle, (int, float)) and isinstance(loaded, (int, float)):
            supports.append(_ev(
                f"空载延迟 {idle:g}ms → 满载 {loaded:g}ms（升高 {item['value']:g}ms）",
                False))
    else:
        idle, loaded = bb.get("idle_rtt_ms"), bb.get("loaded_rtt_ms")
        if isinstance(idle, (int, float)) and isinstance(loaded, (int, float)):
            bloat = bb.get("bloat_ms")
            bloat = bloat if isinstance(bloat, (int, float)) else loaded - idle
            supports.append(_ev(
                f"空载延迟 {idle:g}ms → 满载 {loaded:g}ms（升高 {bloat:g}ms）", False))
    i_grade = _evd_find(ev, "bufferbloat.grade.grade")
    grade = i_grade.get("value") if i_grade is not None else bb.get("grade")
    if grade:
        supports.append(_ev(f"Bufferbloat 等级 {grade}", False))
    excludes = []
    ping = _ping(results, "gateway")
    i_avg = _evd_find(_module_evidence(evd, "gateway"),
                      "gateway.ping.avg_ms")
    i_loss = _evd_find(_module_evidence(evd, "gateway"),
                       "gateway.ping.loss_pct")
    if i_avg is not None and i_loss is not None \
            and isinstance(i_avg.get("value"), (int, float)) \
            and isinstance(i_loss.get("value"), (int, float)):
        g_avg, g_loss = i_avg["value"], i_loss["value"]
    elif ping:
        g_avg, g_loss = ping.get("avg_ms"), ping.get("loss_pct")
    else:
        g_avg = g_loss = None
    if isinstance(g_avg, (int, float)) and isinstance(g_loss, (int, float)) \
            and g_loss < 5:
        excludes.append(_ev(
            f"网关空闲延迟 {g_avg:g}ms 且无丢包（不是链路质量问题）", True))
    return supports, excludes


def _ev_gateway_loss(results, evd=None):
    ping = _ping(results, "gateway") or {}
    supports = []
    item = _evd_find(_module_evidence(evd, "gateway"),
                     "gateway.ping.loss_pct")
    meta = (item or {}).get("metadata") or {}
    if item is not None and isinstance(item.get("value"), (int, float)):
        loss = item["value"]
        sent, recv = meta.get("sent"), meta.get("received")
    else:
        loss = ping.get("loss_pct", 0)
        sent, recv = ping.get("sent"), ping.get("received")
    if isinstance(loss, (int, float)):
        txt = f"网关丢包 {loss:g}%"
        if isinstance(sent, int) and isinstance(recv, int) and sent > 0:
            txt += f"（{sent} 发 {recv} 收）"
        supports.append(_ev(txt, False))
    if isinstance(ping.get("max_ms"), (int, float)):
        supports.append(_ev(f"网关最大延迟 {ping['max_ms']:g}ms", False))
    excludes = []
    item = _ev_external_reachable(results, evd, suffix="（不是运营商外网中断）")
    if item:
        excludes.append(item)
    i_dns = _evd_find(_module_evidence(evd, "dns"),
                      "dns.resolve.success_count")
    if i_dns is not None and (i_dns.get("metadata") or {}).get("total_count"):
        sc = i_dns.get("value") or 0
        tc = i_dns["metadata"]["total_count"]
    else:
        dns = _mod(results, "dns") or {}
        sc, tc = dns.get("success_count", 0) or 0, dns.get("total_count", 0) or 0
    if tc and sc == tc:
        excludes.append(_ev(f"DNS 解析 {sc}/{tc} 全部正常", True))
    return supports, excludes


def _ev_nat_restricted(results, evd=None):
    nat = _mod(results, "nattype") or {}
    supports = []
    ev = _module_evidence(evd, "nattype")
    i_behavior = _evd_find(ev, "nattype.stun.nat_behavior")
    behavior = i_behavior.get("value") if i_behavior is not None \
        else nat.get("nat_behavior")
    if behavior:
        supports.append(_ev(f"NAT 行为：{behavior}", False))
    i_cone = _evd_find(ev, "nattype.stun.cone_type")
    cone = i_cone.get("value") if i_cone is not None else nat.get("cone_type")
    if cone:
        supports.append(_ev(f"锥形类型：{cone}", True))
    excludes = []
    item = _ev_external_reachable(results, evd, suffix="（普通上网 / 网页访问不受影响）")
    if item:
        excludes.append(item)
    return supports, excludes


def _ev_mtu_blackhole(results, evd=None):
    mtu = _mod(results, "mtu") or {}
    supports = []
    ev = _module_evidence(evd, "mtu")
    if ev:
        # 证据优先: probe 阶段已认证的 path_mtu / iface mtu 逐条转写
        for e in ev:
            meta = e.get("metadata", {})
            if e.get("id") == "mtu.probe.path_mtu":
                supports.append(_ev(
                    f"到 {meta.get('target')} 的路径 MTU = {e.get('value')}", False))
            elif e.get("id") == "mtu.iface.mtu":
                v = e.get("value")
                # 老 exe 快照里可能残留回环口 4294967295, 防御性过滤
                if isinstance(v, (int, float)) and _MTU_VALID_MIN <= v <= _MTU_VALID_MAX:
                    supports.append(_ev(
                        f"接口 {meta.get('interface')} MTU = {v}", False))
    else:
        for r in (mtu.get("path_mtus") or []):
            if not r.get("error") and r.get("path_mtu"):
                supports.append(_ev(
                    f"到 {r.get('target')} 的路径 MTU = {r['path_mtu']}", False))
        for lm in _clean_local_mtus(mtu.get("local_mtus")):
            # 生产者 MTUDetector 发的键是 interface (v1.9.2 修正, 勿改回 name)
            supports.append(_ev(
                f"接口 {lm.get('interface')} MTU = {lm['mtu']}", False))
    ts = _mod(results, "tcpstats") or {}
    item = _evd_find(_module_evidence(evd, "tcpstats"),
                     "tcpstats.retrans.retrans_rate_pct")
    if item is not None:
        rate = item.get("value")
    else:
        rate = ts.get("retrans_rate_pct")
    if isinstance(rate, (int, float)) and rate >= 5:
        supports.append(_ev(f"TCP 重传率 {rate:g}% 佐证 (大包在丢)", False))
    excludes = []
    for fn in (_ev_gateway_reachable, _ev_external_reachable):
        item = fn(results, evd)     # v1.9.2 (审查修复): 与 dns_failure 对齐
        if item:
            excludes.append(item)
    return supports, excludes


def _ev_tcp_loss_burst(results, evd=None):
    ts = _mod(results, "tcpstats") or {}
    supports = []
    item = _evd_find(_module_evidence(evd, "tcpstats"),
                     "tcpstats.retrans.retrans_rate_pct")
    if item is not None and isinstance(item.get("value"), (int, float)):
        rate = item["value"]
        meta = item.get("metadata") or {}
        retrans = meta.get("retransmitted", "—")
        sent = meta.get("segments_sent", "—")
    else:
        rate = ts.get("retrans_rate_pct")
        retrans = ts.get("retransmitted", "—")
        sent = ts.get("segments_sent", "—")
    if isinstance(rate, (int, float)):
        supports.append(_ev(
            f"TCP 重传率 {rate:g}% (重传 {retrans} / "
            f"发送 {sent}, 开机累计口径)", False))
    excludes = []
    ev_m = _module_evidence(evd, "mtu")
    if ev_m:
        paths = [e["value"] for e in ev_m if e.get("id") == "mtu.probe.path_mtu"
                 and isinstance(e.get("value"), (int, float))]
        local = [e["value"] for e in ev_m if e.get("id") == "mtu.iface.mtu"
                 and isinstance(e.get("value"), (int, float))]
    else:
        mtu = _mod(results, "mtu") or {}
        paths = [r.get("path_mtu") for r in (mtu.get("path_mtus") or [])
                 if not r.get("error") and r.get("path_mtu")]
        local = [lm["mtu"] for lm in _clean_local_mtus(mtu.get("local_mtus"))]
    if paths and local and max(local) - min(paths) < 100:
        excludes.append(_ev(
            f"路径 MTU ({min(paths)}) 与接口 MTU ({max(local)}) 相符, 已排除 MTU 不匹配", True))
    return supports, excludes


# 规则 id → 证据生成函数
_RC_EVIDENCE_BUILDERS = {
    "dns_failure": _ev_dns_failure,
    "wan_interruption": _ev_wan_interruption,
    "wifi_weak": _ev_wifi_weak,
    "bufferbloat": _ev_bufferbloat,
    "gateway_loss": _ev_gateway_loss,
    "nat_restricted": _ev_nat_restricted,
    # v1.7.0 (PR-F0): 统计层新规则的证据链
    "mtu_blackhole": _ev_mtu_blackhole,
    "tcp_loss_burst": _ev_tcp_loss_burst,
}


def _enrich_diagnosis_evidence(report, results_dict, evidence_by_module=None):
    """给 DiagnosisReport 里每个 RootCause 补 supports / excludes。

    evidence_by_module: 模块自证证据映射 (LAST_RUN["evidence"], v1.9.0) —
    builder 的支持/排除项优先取此处的 probe 认证数值。
    单条规则生成失败不影响整份报告 (吞异常后该根因退化为无证据链,
    与 v1.4.x 渲染行为一致)。
    """
    for rc in getattr(report, "root_causes", []) or []:
        fn = _RC_EVIDENCE_BUILDERS.get(getattr(rc, "id", ""))
        if not fn:
            continue
        try:
            supports, excludes = fn(results_dict, evidence_by_module)
        except Exception:
            continue
        rc.supports = [s for s in (supports or []) if s and s.get("text")]
        rc.excludes = [e for e in (excludes or []) if e and e.get("text")]
    return report


def _build_diagnosis_with_evidence(results_dict, rule_filter=None,
                                   evidence_by_module=None):
    """diagnose() + 证据链增强 (报告渲染入口)。

    rule_filter: 透传 diagnose() 的场景规则过滤 — 保证导出报告里的根因
                 与完成屏一致 (gaming 报告不再夹带屏幕上已隐藏的 wifi_weak)。
    evidence_by_module: 模块自证证据映射 (v1.9.0), 透传给各证据链 builder。
    """
    return _enrich_diagnosis_evidence(
        diagnose(results_dict, rule_filter=rule_filter), results_dict,
        evidence_by_module)


# 规则注册表 (C1 · v1.6.1 收敛为单一有序注册表): ALL_RULES / _RULE_BY_ID /
# _RULE_ID_OF 全部由 _RULE_REGISTRY 派生 — 新增规则只在此追加一行,
# 杜绝多份手工注册表漂移导致规则静默失效 (v1.6.0 审查 #10)。
_RULE_REGISTRY = [
    # (规则 id, 规则函数): id 与 RootCause(id=...) / _RC_EVIDENCE_BUILDERS 同源
    ("dns_failure", _rule_dns_failure),
    ("wan_interruption", _rule_wan_interruption),
    ("wifi_weak", _rule_wifi_weak),
    ("bufferbloat", _rule_bufferbloat),
    ("gateway_loss", _rule_gateway_loss),
    ("nat_restricted", _rule_nat_restricted),
    # v1.7.0 (PR-F0): 统计层根因 — 不依赖抓包, mtu/tcpstats 模块数据即可判定
    ("mtu_blackhole", _rule_mtu_blackhole),
    ("tcp_loss_burst", _rule_tcp_loss_burst),
]
ALL_RULES = [fn for _rid, fn in _RULE_REGISTRY]
_RULE_BY_ID = dict(_RULE_REGISTRY)
# 函数 → id 反向映射 (兜底评估时按 PROFILE_RULE_EXCLUDES 跳过)
_RULE_ID_OF = {fn: rid for rid, fn in _RULE_REGISTRY}


def diagnose(results_dict, rule_filter=None):
    """根因分析主入口 (C1 + C2). 评估内置规则, 返回 DiagnosisReport.

    results_dict: run_diagnostics 输出的 full dict ({key: results_dict})
    rule_filter: 场景 profile id (PR-B · v1.6.0)。只评估该场景相关规则
                 (PROFILE_RULES), 避免 gaming 报 wifi 弱等无关根因。
                 过滤后无命中时退回全规则评估 —— 不把异常藏起来,
                 与 HTML 报告"无根因时所有问题模块都展开"同哲学。
                 为 None 时评估全部规则 (v1.5.x 行为不变)。
    """
    def _run_rules(rule_list):
        """评估一组规则 → (命中的根因列表, 实际评估条数)。"""
        fired, n = [], 0
        for rule in rule_list:
            n += 1
            rc = rule(results_dict)
            if rc is not None:
                fired.append(rc)
        return fired, n

    if rule_filter and PROFILE_RULES.get(rule_filter):
        excludes = set(PROFILE_RULE_EXCLUDES.get(rule_filter) or [])
        first = [_RULE_BY_ID[i] for i in PROFILE_RULES[rule_filter]
                 if i in _RULE_BY_ID]
        root_causes, rules_evaluated = _run_rules(first)
        if not root_causes:
            # 场景规则过滤后无命中 → 兜底补评 (不能把异常藏起来)。
            # 场景明确排除的规则 (PROFILE_RULE_EXCLUDES) 即使兜底也禁止评估,
            # 防止排除规则借兜底路径绕回 (gaming 报 wifi 弱)。
            # v1.6.1: 只补评首轮没跑过的规则, 不再整轮重复评估 (审查 #9);
            # rules_evaluated 始终按实际评估条数累计。
            rest = [r for r in ALL_RULES
                    if r not in first and _RULE_ID_OF.get(r) not in excludes]
            fired, n = _run_rules(rest)
            root_causes = fired
            rules_evaluated += n
    else:
        root_causes, rules_evaluated = _run_rules(ALL_RULES)
    # v1.5.3: 按严重度降序 (同级保持注册表顺序)。root_causes[0] 会被 HTML 报告
    # 的模块折叠策略当作「首要根因」、CLI/报障工单按序展示 — 注册表顺序
    # (dns 在前) 会让 HIGH 的 dns_failure 压住 CRITICAL 的 wan_interruption,
    # 最严重问题的证据反而被折叠到一次点击之后。Severity 定义顺序即升序。
    _sev_rank = {s: i for i, s in enumerate(Severity)}
    root_causes.sort(key=lambda rc: -_sev_rank.get(rc.severity, len(_sev_rank)))
    # overall_confidence: 加权平均 (severity 权重)
    if root_causes:
        sev_weight = {Severity.CRITICAL: 3.0, Severity.HIGH: 2.0,
                      Severity.MEDIUM: 1.0, Severity.LOW: 0.5,
                      Severity.INFO: 0.2}
        total_w = sum(sev_weight.get(rc.severity, 1.0) for rc in root_causes)
        weighted = sum(rc.confidence * sev_weight.get(rc.severity, 1.0)
                       for rc in root_causes)
        overall_confidence = weighted / total_w if total_w > 0 else 0.0
    else:
        overall_confidence = 1.0  # 无故障, 高置信度
    return DiagnosisReport(
        root_causes=root_causes,
        overall_confidence=overall_confidence,
        timestamp=datetime.now().isoformat(),
        rules_evaluated=rules_evaluated,
        rules_fired=len(root_causes),
    )


# ────────────────────────────────────────────────────────────────────────────
# 5 个 Profile 定义 (C3)
# ────────────────────────────────────────────────────────────────────────────
# 用户场景驱动的模块组合, 不再要求客户背 23 个模块名.
# 后续 C4 实现 netpulse diagnose <profile> 子命令.

DIAGNOSE_PROFILES = {
    # 网速慢/卡顿: 链路 + 干扰 + 测速 + 缓冲膨胀 + TCP 质量 + DNS
    # (v1.7.0: 补 tcpstats — tcp_loss_burst 规则需要重传率数据)
    "slow": ["gateway", "wifi", "speedtest", "bufferbloat", "tcp", "dns",
             "tcpstats"],
    # 频繁断网: 链路 + 外网 + DNS + TCP + 环路检测 (monitor 是 CLI 模式不是模块)
    "disconnect": ["gateway", "external", "dns", "tcp", "loop"],
    # 网页打不开/慢: 网关 + 外网 + DNS + TCP + HTTP + TCP 质量 + MTU + 路由
    # (v1.6.1: 补 gateway/external — dns_failure / wan_interruption / gateway_loss
    #  三条 web 规则都依赖网关或外网数据, 缺采集会让 web 场景永远零根因)
    "web": ["gateway", "external", "dns", "tcp", "web", "tcpstats", "mtu", "route"],
    # 游戏卡顿/延迟高: 网关 + 抖动/丢包 + NAT + Bufferbloat + MTU + TCP
    "gaming": ["gateway", "tcp", "nattype", "bufferbloat", "mtu", "tcpstats"],
    # WiFi 不稳/信号弱: WiFi + 网关 + LAN
    "wifi": ["wifi", "gateway", "lan"],
}

# 场景 profile → 参与根因评估的规则 id (PR-B · v1.6.0)
# 只评估该场景相关规则, 避免无关根因 (如 gaming 场景报 "WiFi 信号弱" 噪音)。
# 规则集取舍:
#   - slow 含 wifi_weak: 装维现场 "网慢" 多数先看 WiFi 信号 (决策点 7.4 默认含)
#   - gaming 必不含 wifi_weak: 游戏卡顿报 WiFi 弱 = 噪音 (用户拍板)
#   - disconnect/web 聚焦连通性规则 (WAN 中断 / 网关丢包 / DNS)
PROFILE_RULES = {
    "slow": ["bufferbloat", "gateway_loss", "dns_failure", "wifi_weak",
             "tcp_loss_burst"],
    "disconnect": ["wan_interruption", "gateway_loss", "dns_failure"],
    "web": ["dns_failure", "wan_interruption", "gateway_loss",
            "mtu_blackhole", "tcp_loss_burst"],
    "gaming": ["gateway_loss", "bufferbloat", "nat_restricted",
               "mtu_blackhole", "tcp_loss_burst"],
    "wifi": ["wifi_weak", "gateway_loss"],
}

# 场景明确排除的规则 id (PR-B · v1.6.0): 即使「无命中退回全规则」兜底
# 触发也禁止评估。防止排除规则借兜底路径绕回 (如 gaming 场景报 wifi 弱)。
PROFILE_RULE_EXCLUDES = {
    "gaming": ["wifi_weak"],
}

# 场景中文标签 (PR-A · v1.6.0 主菜单 / 完成屏 / 报告文件名用)
SCENE_LABELS = {
    "slow": "网络很慢",
    "disconnect": "经常断网",
    "web": "网页打不开",
    "gaming": "游戏卡顿",
    "wifi": "WiFi 信号差",
}
# 主菜单数字键 → profile id
SCENE_MENU_KEYS = {
    "1": "slow",
    "2": "disconnect",
    "3": "web",
    "4": "gaming",
    "5": "wifi",
}


# ────────────────────────────────────────────────────────────────────────────
# _print_diagnosis: 格式化输出根因报告 (阶段 C · CLI)
# ────────────────────────────────────────────────────────────────────────────
# 用户场景下"先看根因 → 再看证据": 顶部突出主要问题 + 置信度 + 建议,
# 客户不必读 23 项原始数据.
# 注意: C_RED/C_GREEN 等 ANSI 常量在 SECTION 5 才定义, 这里用函数延迟计算
# 避免模块加载时前置引用 NameError.


def _severity_color(sev):
    """Severity → ANSI 颜色代码 (C_RED 等在 SECTION 5 定义, 延迟计算)."""
    return {
        Severity.CRITICAL: C_RED,
        Severity.HIGH: C_RED,
        Severity.MEDIUM: C_YELLOW,
        Severity.LOW: C_GRAY,
        Severity.INFO: C_GRAY,
    }.get(sev, C_WHITE)


def _conf_band(confidence):
    """置信度分档显示 (审计 P1-04): 内部 0.0-1.0 数值是规则设计值而非统计
    概率, UI 不再伪装成"xx%"伪精确数字, 呈现 高/中/低 三档;
    JSON 里仍保留原始数值供程序消费。"""
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return "低置信度"
    if c >= 0.75:
        return "高置信度"
    if c >= 0.5:
        return "中置信度"
    return "低置信度"


def _print_diagnosis(diagnosis):
    """CLI: 格式化打印 DiagnosisReport (根因 + 置信度 + 建议).

    v1.9.8: 交互 TTY 下, 建议里带 "(管理员)" 标记的修复命令 (如 MTU netsh)
    打印完提供一键以管理员身份执行 (cmd /k 独立窗口, 可核对结果再关);
    非 TTY / 用户跳过时零打扰。
    """
    if not diagnosis.root_causes:
        print(_c(f"  ✓ 根因分析: 未发现故障 "
                 f"(评估 {diagnosis.rules_evaluated} 条规则)", C_GREEN))
        return
    print(_c(f"  🔴 根因分析 ({diagnosis.rules_fired}/{diagnosis.rules_evaluated} "
             f"条规则触发, 整体{_conf_band(diagnosis.overall_confidence)})",
             C_BOLD))
    print()
    for i, rc in enumerate(diagnosis.root_causes, 1):
        color = _severity_color(rc.severity)
        print(_c(f"  [{i}] {rc.severity.value.upper()} · {rc.title}", color))
        print(f"      类别: {rc.category} | {_conf_band(rc.confidence)}")
        print(f"      {rc.description}")
        if rc.affected_modules:
            print(f"      影响模块: {', '.join(rc.affected_modules)}")
        if rc.recommendations:
            print(_c(f"      建议:", C_CYAN))
            for r in rc.recommendations:
                print(f"        {r}")
        print()
    # v1.9.8 遗留项 1: 工程师向修复命令不再要求用户手动开管理员窗口
    _offer_admin_fix_shell(_extract_admin_fix_commands(diagnosis.root_causes))


def _build_trouble_ticket_text(report, diagnosis_dict):
    """生成"一句话报障"纯文本 (v1.5.0).

    客户真正想要的是"你帮我把问题说清楚, 我拿给客服", 而不是 P95 / TTFB / NAT Cone。
    结构: 时间 + 总分 + 主要问题 + 已排除 + 建议首条。
    """
    import html as _html
    if not report:
        return ""
    g = report.get("generated_at")
    g_s = g.strftime("%Y-%m-%d %H:%M") if hasattr(g, "strftime") else str(g or "")
    health = report.get("health") or {}
    lines = [f"{g_s} · {report.get('app', 'NetPulse')} v{report.get('version', '')}"]

    scope = ""
    sel, tot = report.get("selected_modules"), report.get("total_modules")
    if isinstance(sel, int) and isinstance(tot, int) and tot and sel < tot:
        scope = f"（本次检测 {sel}/{tot} 项）"

    rcs = (diagnosis_dict or {}).get("root_causes") or []
    if not rcs:
        lines.append(f"网络检测未发现明确故障{scope}，"
                     f"健康度 {health.get('score', 0)}/100"
                     f"（{health.get('label', '')}）。")
        return "\n".join(lines)

    lines.append(f"健康度 {health.get('score', 0)}/100"
                 f"（{health.get('label', '')}）{scope}，检测到 "
                 f"{len(rcs)} 个主要问题：")
    for i, rc in enumerate(rcs, 1):
        lines.append(f"{i}. {rc.get('title', '')}（{_conf_band(rc.get('confidence'))}）")
        desc = (rc.get("description") or "").strip()
        if desc:
            lines.append(f"   现象：{desc}")
        # 关键证据: 只取问题项 (ok=False), 客服不需要看"排除了什么"的全部细节
        bad = [s.get("text", "") for s in (rc.get("supports") or [])
               if not s.get("ok") and s.get("text")]
        if bad:
            lines.append("   实测：" + "；".join(bad))
        recs = rc.get("recommendations") or []
        if recs:
            # 只带首条建议: 报障文本要短, 完整建议看报告本身
            lines.append("   建议：" + str(recs[0]))
    return "\n".join(lines)


def _render_diagnosis_section_html(diagnosis_dict, report=None):
    """阶段 C · v1.3.0: HTML 报告根因摘要区块.

    输入: build_report() 输出的 diagnosis dict (to_dict() 结果)
          report (v1.5.0, 可选): 完整 report, 用于生成"一句话报障"
    输出: HTML section 字符串 (嵌入到 hero 之后), 无根因时返回 ""
    """
    import html as _html
    if not diagnosis_dict:
        return ""
    root_causes = diagnosis_dict.get("root_causes") or []
    if not root_causes:
        # 健康时显示一行轻提示
        return ('<section class="diagnosis healthy" id="diagnosis">'
                '<div class="dhead">'
                '<span class="dbadge ok">✓ 无故障</span>'
                f'<span class="dconf">整体{_conf_band(diagnosis_dict.get("overall_confidence", 1.0))}, '
                f'评估 {diagnosis_dict.get("rules_evaluated", 0)} 条规则'
                '</span></div>'
                '</section>')
    cards = []
    for i, rc in enumerate(root_causes, 1):
        sev = rc.get("severity", "medium")
        sev_label = {"critical": "严重", "high": "高",
                     "medium": "中", "low": "低"}.get(sev, sev)
        conf_band = _conf_band(rc.get("confidence", 0))
        recs = rc.get("recommendations") or []
        recs_html = "".join(f"<li>{_html.escape(str(r))}</li>" for r in recs)
        affected = ", ".join(rc.get("affected_modules") or []) or " - "
        # v1.5.0 证据链: 「为什么这样判断 / 已基本排除」—— 把"事实"与"判断"
        # 分开写, 装维拿这份报告跟客户解释时最有用的就是这两块
        sup_items, exc_items = [], []
        for s in rc.get("supports") or []:
            txt = str(s.get("text") or "").strip()
            if not txt:
                continue
            cls = "yes" if s.get("ok") else "no"
            sup_items.append(
                f'<li class="{cls}">{"✓" if s.get("ok") else "✕"} {_html.escape(txt)}</li>')
        for e in rc.get("excludes") or []:
            txt = str(e.get("text") or "").strip()
            if txt:
                exc_items.append(f'<li class="yes">✓ {_html.escape(txt)}</li>')
        evidence_html = ""
        if sup_items or exc_items:
            sup_block = (f'<div class="rev-t">为什么这样判断</div>'
                         f'<ul class="rev-list">{"".join(sup_items)}</ul>') if sup_items else ""
            exc_block = (f'<div class="rev-t">已基本排除</div>'
                         f'<ul class="rev-list">{"".join(exc_items)}</ul>') if exc_items else ""
            evidence_html = f'<div class="rev">{sup_block}{exc_block}</div>'
        # v1.5.0 复测命令卡: 静态 HTML 无法直接执行, 但可以给一条可复制的命令
        mods = [m for m in (rc.get("affected_modules") or []) if m]
        cmd = "netpulse " + " ".join(mods) if mods else "netpulse all"
        cmd_html = (f'<div class="cmd-card"><span class="cmd-lab">建议复测</span>'
                    f'<code>{_html.escape(cmd)}</code>'
                    f'<button type="button" class="copy-btn" '
                    f'data-copy="{_html_attr(cmd)}">复制命令</button></div>')
        cards.append(
            f'<div class="rcard severity-{_html_attr(sev)}">'
            f'<div class="rhead">'
            f'<span class="rbadge">{_html.escape(sev_label)}</span>'
            f'<strong>{_html.escape(rc.get("title", ""))}</strong>'
            f'<span class="rconf">{conf_band}</span>'
            f'</div>'
            f'<p class="rdesc">{_html.escape(rc.get("description", ""))}</p>'
            f'{evidence_html}'
            f'<p class="rmods">影响模块: {_html.escape(affected)}</p>'
            f'<details><summary>建议 ({len(recs)} 条)</summary>'
            f'<ul>{recs_html}</ul></details>'
            f'{cmd_html}'
            f'</div>')
    header = (
        f'<div class="dhead">'
        f'<span class="dbadge warn">🔴 {len(root_causes)} 个主要问题</span>'
        f'<span class="dconf">整体{_conf_band(diagnosis_dict.get("overall_confidence", 0))}, '
        f'触发 {diagnosis_dict.get("rules_fired", 0)}/{diagnosis_dict.get("rules_evaluated", 0)} 条规则'
        f'</span></div>')
    # v1.5.0 一句话报障: 客户不想看 P95 / TTFB / NAT Cone, 只想要一段能直接
    # 发给客服 / 运营商的话。长文本走 <pre> + JS 读 textContent, 不塞进属性
    ticket_html = ""
    ticket = _build_trouble_ticket_text(report, diagnosis_dict)
    if ticket:
        ticket_html = (
            f'<div class="ticket">'
            f'<div class="ticket-head">📋 可直接提交给运营商 / 技术支持'
            f'<button type="button" class="copy-btn" '
            f'data-copy-from="np-ticket">复制报障描述</button></div>'
            f'<pre class="ticket-body" id="np-ticket">{_html.escape(ticket)}</pre>'
            f'</div>')
    return (f'<section class="diagnosis" id="diagnosis">'
            f'<h2>主要问题</h2>{header}{"".join(cards)}{ticket_html}</section>')


# === Diagnosis CSS (阶段 C · v1.3.0) ===
# 注入到 HTML 报告头部 <style> 内部 (紧贴现有 _BRAND_HEADER_CSS 之后).
# 注意: 不嵌套 <style> 标签, 由调用方在 <style> 块内嵌.
_DIAGNOSIS_CSS = """
.diagnosis { padding: 16px 20px; margin: 16px 0; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
.diagnosis h2 { margin: 0 0 12px; font-size: 18px; color: #1e293b; }
.diagnosis .dhead { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
/* v1.9.5: 无故障卡片左对齐单行 — 整句水平居中不符合阅读习惯(中文用户习惯
   结论靠左一眼扫过), 恢复 flex-start 左对齐; 保留 v1.9.4 紧凑高度
   (padding 9px / row-gap 4px / line-height 1.4) 消除"第二行空白"观感 */
.diagnosis.healthy { padding: 9px 20px; }
.diagnosis.healthy .dhead { margin-bottom: 0; flex-wrap: wrap; row-gap: 4px; line-height: 1.4; }
.diagnosis.healthy .dbadge.ok { font-size: 14px; padding: 5px 14px; }
.diagnosis .dbadge { padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 13px; }
.diagnosis .dbadge.ok { background: #dcfce7; color: #166534; }
.diagnosis .dbadge.warn { background: #fee2e2; color: #991b1b; }
.diagnosis .dconf { color: #64748b; font-size: 13px; }
.diagnosis .rcard { padding: 12px 16px; border-left: 4px solid #94a3b8; margin-bottom: 12px; background: #f8fafc; border-radius: 0 6px 6px 0; }
.diagnosis .rcard.severity-critical { border-color: #dc2626; background: #fef2f2; }
.diagnosis .rcard.severity-high { border-color: #ea580c; background: #fff7ed; }
.diagnosis .rcard.severity-medium { border-color: #d97706; background: #fffbeb; }
.diagnosis .rcard.severity-low { border-color: #65a30d; }
.diagnosis .rhead { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }
.diagnosis .rbadge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #e2e8f0; color: #334155; }
.diagnosis .rcard.severity-critical .rbadge { background: #dc2626; color: #fff; }
.diagnosis .rcard.severity-high .rbadge { background: #ea580c; color: #fff; }
.diagnosis .rcard.severity-medium .rbadge { background: #d97706; color: #fff; }
.diagnosis .rhead strong { flex: 1; font-size: 15px; color: #1e293b; }
.diagnosis .rconf { font-size: 13px; color: #475569; font-weight: 600; }
.diagnosis .rdesc { margin: 6px 0; color: #334155; font-size: 13px; line-height: 1.5; }
.diagnosis .rmods { margin: 4px 0; color: #64748b; font-size: 12px; }
.diagnosis details { margin-top: 8px; }
.diagnosis details summary { cursor: pointer; color: #0891b2; font-size: 13px; padding: 4px 0; }
.diagnosis details ul { margin: 6px 0 0 0; padding-left: 20px; }
.diagnosis details li { margin: 4px 0; color: #334155; font-size: 13px; line-height: 1.5; }
/* v1.5.0 证据链: 事实(支持项) / 排除项 分离展示 */
.diagnosis .rev { margin: 10px 0; padding: 10px 14px; background: #fff; border: 1px solid #e6e9f0; border-radius: 8px; }
.diagnosis .rev-t { font-size: 12px; font-weight: 600; color: #475569; margin: 6px 0 4px; letter-spacing: .3px; }
.diagnosis .rev-t:first-child { margin-top: 0; }
.diagnosis .rev-list { list-style: none; margin: 0; padding: 0; }
.diagnosis .rev-list li { font-size: 12.5px; line-height: 1.75; color: #334155; }
.diagnosis .rev-list li.yes { color: #166534; }
.diagnosis .rev-list li.no { color: #991b1b; font-weight: 600; }
/* v1.5.0 复测命令卡 */
.diagnosis .cmd-card { display: flex; align-items: center; gap: 8px; margin-top: 10px; padding: 7px 10px; background: #0f172a; border-radius: 8px; }
.diagnosis .cmd-card .cmd-lab { font-size: 11px; color: #94a3b8; flex: none; }
.diagnosis .cmd-card code { font-family: Cascadia Mono,Consolas,monospace; font-size: 12.5px; color: #e2e8f0; flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; }
.diagnosis .cmd-card .copy-btn { font: inherit; font-size: 11.5px; padding: 3px 10px; border: 1px solid rgba(255,255,255,.25); background: rgba(255,255,255,.08); color: #e2e8f0; border-radius: 6px; cursor: pointer; flex: none; }
.diagnosis .cmd-card .copy-btn:hover { background: rgba(255,255,255,.18); }
/* v1.5.0 一句话报障 */
.ticket { margin-top: 14px; padding: 12px 16px; background: #f8fafc; border: 1px dashed #94a3b8; border-radius: 8px; }
.ticket .ticket-head { display: flex; align-items: center; gap: 10px; font-size: 13px; font-weight: 600; color: #1e293b; margin-bottom: 8px; }
.ticket .ticket-head .copy-btn { margin-left: auto; font: inherit; font-size: 11.5px; padding: 3px 10px; border: 1px solid #cbd5e1; background: #fff; color: #1e293b; border-radius: 6px; cursor: pointer; flex: none; }
.ticket .ticket-head .copy-btn:hover { background: #eef2f7; }
.ticket .ticket-body { margin: 0; font: 12px/1.75 Cascadia Mono,Consolas,monospace; color: #334155; white-space: pre-wrap; word-break: break-word; }
.copy-btn.done { background: #16a34a !important; border-color: #16a34a !important; color: #fff !important; }
@media print {
  .diagnosis details { open: true; }
  .diagnosis details ul { display: block !important; }
  .copy-btn { display: none; }
}
"""


# ────────────────────────────────────────────────────────────────────────────
# 阶段 D · v1.4.0: --debug-bundle 调试包 (含脱敏)
# ────────────────────────────────────────────────────────────────────────────
# 用户场景: 上报 bug / 远端排障, 需要把"系统信息 + 诊断结果 + log"打包
# 发送给开发者. 隐私敏感 (用户偏好: 分发物严禁暴露本地用户名),
# 因此默认脱敏: SSID / MAC / 公网 IP / hostname.

def _is_private_ipv4(ip):
    """内网/保留/组播段返回 True (排障需要, 脱敏时保留)."""
    try:
        a, b = int(ip.split(".")[0]), int(ip.split(".")[1])
    except (ValueError, IndexError):
        return True
    return (a in (0, 10, 127) or a >= 224
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254))


def _mask_public_ipv4_text(text):
    """把文本里的公网 IPv4 (可带 :port) 打码为 a.b.X.X; 内网 IP 原样保留."""
    def _sub(m):
        ip = m.group(1)
        if _is_private_ipv4(ip):
            return m.group(0)
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.X.X" + (":X" if m.group(2) else "")
    return re.sub(r"\b(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?\b", _sub, text)


# IPv6 文本匹配: 全形式 / 首尾 :: / 中间单 :: (覆盖 NAT/egress summary 里的真实形态)
_IPV6_TEXT_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:.])")


def _mask_public_ipv6_text(text):
    """把文本里的公网 IPv6 (2000::/3 全球单播) 打码; fe80/fd 等本地段保留."""
    def _sub(m):
        addr = m.group(0).lower()
        if addr.startswith(("fe", "fc", "fd")) or addr.startswith("::"):
            return m.group(0)
        groups = [g for g in addr.split(":") if g]
        head = ":".join(groups[:2]) if len(groups) >= 2 else groups[0]
        return f"{head}:…:REDACTED"
    return _IPV6_TEXT_RE.sub(_sub, text)


def _redact_text_value(value):
    """对自由文本 (summary/message/error 等) 做值级打码."""
    return _mask_public_ipv6_text(_mask_public_ipv4_text(value))


# 需要值级文本打码的字段 (文案里常嵌公网 IP:port, 如 NAT summary 的映射地址)
_REDACT_TEXTY_KEYS = {"summary", "message", "detail", "action", "description",
                      "error", "assessment", "verdict", "note", "title", "text"}


def _redact_value(key, value):
    """脱敏单个字段值. 命中隐私字段返回 mask, 否则原样返回."""
    key_l = key.lower()
    # STUN 映射端口 (int): 与 mapped_ip 组合即出口身份, 一并打码
    if "mapped_port" in key_l:
        return "X"
    if not isinstance(value, str) or not value:
        return value
    # MAC 地址 (XX:XX:XX:XX:XX:XX 或 XX-XX-XX-XX-XX-XX 格式)
    if "mac" in key_l and re.match(r"^[0-9a-fA-F:-]+$", value):
        return "XX:XX:XX:XX:XX:XX"
    # SSID (任意字符串)
    if "ssid" in key_l:
        return "***"
    # hostname (DESKTOP-XXXX 或)
    if "hostname" in key_l or "host_name" in key_l:
        return "host-REDACTED"
    # STUN 映射地址 (mapped_ip/mapped_addr/public_ip_tcp): 用户出口身份,
    # 值形如 "1.2.3.4" 或 "1.2.3.4:50000" (内网映射不会被 STUN 返回, 全打码)
    if any(t in key_l for t in ("mapped_ip", "mapped_addr", "public_ip_tcp")):
        return _mask_public_ipv4_text(value)
    # 公网 IP 字段: IPv4 打末两段, IPv6 全球单播保前两组
    if "public_ip" in key_l or "ipv6" in key_l:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
            parts = value.split(".")
            return f"{parts[0]}.{parts[1]}.X.X"
        if ":" in value:
            return _mask_public_ipv6_text(value)
    # 文案字段: 值级打码 (嵌在中文句子里的公网 ip:port / IPv6)
    if key_l in _REDACT_TEXTY_KEYS:
        return _redact_text_value(value)
    return value


def _redact_dict(d):
    """递归脱敏 dict, 处理 dict/list/str 嵌套."""
    if not isinstance(d, dict):
        return d
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = _redact_dict(v)
        elif isinstance(v, list):
            out[k] = [_redact_dict(x) if isinstance(x, dict)
                      else _redact_value(k, x) for x in v]
        else:
            out[k] = _redact_value(k, v)
    return out


def _export_debug_bundle(out_dir):
    """阶段 D · v1.4.0: 生成脱敏调试包.

    流程:
      1. 跑一次全诊断 (若 LAST_RUN 不存在)
      2. 脱敏 (SSID / MAC / 公网 IP / hostname)
      3. 写 system.json + diagnostic.json + evidence.json + netpulse.log
      4. 打包 zip, 输出到 out_dir
    """
    # 1. 确保有诊断数据
    if not LAST_RUN:
        print(_c("  首次生成 debug-bundle, 跑全诊断 (不含压力级 tcpcc, 约 30-120 秒)...",
                 C_GRAY))
        run_diagnostics(all_module_keys())
    if not LAST_RUN:
        print(_c("  ✗ 跑诊断失败, 无法生成 debug-bundle", C_RED))
        return
    # 2. 脱敏
    try:
        sys_info_redacted = _redact_dict(dict(LAST_RUN.get("system", {})))
        diag_redacted = {k: _redact_dict(v) if isinstance(v, dict)
                         else v for k, v in LAST_RUN.get("results", {}).items()}
        ev_redacted = _redact_dict(dict(LAST_RUN.get("evidence") or {}))
    except Exception as e:
        print(_c(f"  ✗ 脱敏失败: {e}", C_RED))
        return
    # 3. 输出目录
    out_dir_abs = os.path.abspath(out_dir)
    os.makedirs(out_dir_abs, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"netpulse-debug-{timestamp}"
    system_path = os.path.join(out_dir_abs, f"{base}-system.json")
    diag_path = os.path.join(out_dir_abs, f"{base}-diagnostic.json")
    ev_path = os.path.join(out_dir_abs, f"{base}-evidence.json")
    log_path = os.path.join(out_dir_abs, f"{base}-netpulse.log")
    zip_path = os.path.join(out_dir_abs, f"{base}.zip")
    # 4. 写 JSON 文件
    with open(system_path, "w", encoding="utf-8") as f:
        json.dump(sys_info_redacted, f, ensure_ascii=False, indent=2, default=str)
    with open(diag_path, "w", encoding="utf-8") as f:
        json.dump(diag_redacted, f, ensure_ascii=False, indent=2, default=str)
    with open(ev_path, "w", encoding="utf-8") as f:
        json.dump(ev_redacted, f, ensure_ascii=False, indent=2, default=str)
    # log: 运行概要 (模块状态 + 模块级 error; 阶段 E 可接 Python logging 模块)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"NetPulse v{APP_VERSION} debug bundle\n")
        f.write(f"Generated at: {datetime.now().isoformat()}\n")
        f.write("Redacted: SSID / MAC / 公网 IPv4+IPv6 / STUN 映射地址 / hostname\n")
        f.write(f"Schema version: {SCHEMA_VERSION}\n")
        f.write("-" * 60 + "\n")
        f.write("模块运行状态:\n")
        for k, st in (LAST_RUN.get("status") or {}).items():
            f.write(f"  [{st}] {k}\n")
        f.write(f"运行模块: {', '.join(LAST_RUN.get('keys') or [])}\n")
        for k, res in (LAST_RUN.get("results") or {}).items():
            err = res.get("error") if isinstance(res, dict) else None
            if err:
                f.write(f"  ERROR {k}: {_redact_text_value(str(err)[:200])}\n")
    # 5. zip
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(system_path, os.path.basename(system_path))
            zf.write(diag_path, os.path.basename(diag_path))
            zf.write(ev_path, os.path.basename(ev_path))
            zf.write(log_path, os.path.basename(log_path))
    except Exception as e:
        print(_c(f"  ✗ zip 打包失败: {e}", C_RED))
        return
    # 6. 清理临时文件
    for p in (system_path, diag_path, ev_path, log_path):
        try:
            os.remove(p)
        except OSError:
            pass
    print(_c(f"  ✓ 调试包已生成: {os.path.abspath(zip_path)}", C_GREEN))
    print(_c(f"  含 {os.path.basename(zip_path)} (zip: system.json + diagnostic.json"
             f" + evidence.json + netpulse.log)", C_GRAY))


# ============================================================
# PIP 镜像自动选源
# ============================================================
#
# 国内网络环境下, pypi.org 经常卡到超时 (TCP RST / 极慢 / 间歇性失败),
# 装 scapy 等依赖会卡 5-10 分钟。自动探测并切到国内镜像:
#   1. --pip-mirror CLI 显式指定 (优先级最高)
#   2. PIP_INDEX_URL 环境变量
#   3. 探测国内镜像候选, 选第一个可达的
#   4. PyPI 官方 (None, 让 pip 走默认)
#
# 探测策略: HEAD 请求 2s 超时, 只在首次调用时探测, 缓存结果。
# 避免每次 pip install 都重新探测 (安装期间会调多次)。

_PIP_MIRROR_CANDIDATES = [
    "https://pypi.tuna.tsinghua.edu.cn/simple",       # 清华
    "https://mirrors.aliyun.com/pypi/simple",         # 阿里云
    "https://pypi.mirrors.ustc.edu.cn/simple",        # 中科大
    "https://mirrors.cloud.tencent.com/pypi/simple",  # 腾讯云
]
_PIP_MIRROR_REACHABLE_CACHE = {}  # url -> bool (可达性探测结果缓存)
_PIP_MIRROR_RESOLVED = None      # (url_or_None, source_desc) 全局一次解析


def _probe_pip_mirror(url, timeout=2.0):
    """探测单个 pip 镜像是否可达, HEAD 请求, 超时即不可达。"""
    if url in _PIP_MIRROR_REACHABLE_CACHE:
        return _PIP_MIRROR_REACHABLE_CACHE[url]
    try:
        req = Request(url.rstrip("/") + "/", method="HEAD",
                      headers={"User-Agent": "NetPulse/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            ok = 200 <= resp.status < 500  # 4xx 算可达 (只是路径不对)
    except Exception:
        ok = False
    _PIP_MIRROR_REACHABLE_CACHE[url] = ok
    return ok


def _resolve_pip_mirror(explicit=None):
    """选一个能用的 pip 镜像。

    返回 (url_or_None, source_desc):
      - url_or_None: 选中的镜像, None 表示用 pip 默认
      - source_desc: 选源原因 (用于日志展示)

    注意: 结果在一次会话内只解析一次, 后续直接返回缓存。pip install
    期间会被调多次 (splash 一次, 实际装又调), 重探测会拖慢。
    """
    global _PIP_MIRROR_RESOLVED
    if _PIP_MIRROR_RESOLVED is not None:
        return _PIP_MIRROR_RESOLVED

    if explicit:
        _PIP_MIRROR_RESOLVED = (explicit, "CLI 显式指定")
        return _PIP_MIRROR_RESOLVED
    env_url = (os.environ.get("PIP_INDEX_URL") or "").strip()
    if env_url:
        _PIP_MIRROR_RESOLVED = (env_url, "环境变量 PIP_INDEX_URL")
        return _PIP_MIRROR_RESOLVED

    # 探测国内镜像候选
    for url in _PIP_MIRROR_CANDIDATES:
        if _probe_pip_mirror(url):
            _PIP_MIRROR_RESOLVED = (url, "国内镜像自动探测")
            return _PIP_MIRROR_RESOLVED

    # 全部不可达: 用 PyPI 默认
    _PIP_MIRROR_RESOLVED = (None, "PyPI 默认 (国内镜像均不可达)")
    return _PIP_MIRROR_RESOLVED


def reset_pip_mirror_cache():
    """测试用: 重置选源缓存以重新探测。"""
    global _PIP_MIRROR_RESOLVED
    _PIP_MIRROR_RESOLVED = None
    _PIP_MIRROR_REACHABLE_CACHE.clear()


def _download_file(url, dest, timeout=180):
    """下载文件到 dest。返回 (ok, msg)。"""
    try:
        with _urlopen_with_proxy(url, timeout=timeout) as resp, open(dest, "wb") as f:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
        return True, ""
    except Exception as e:
        return False, f"下载失败: {e}"


def _install_npcap():
    """下载并以静默方式安装 Npcap (需管理员权限)。返回 (ok, msg)。

    v1.9.7 PR-3: 保留管理员守卫 (函数语义不变)。交互路径的「一键提权重启」
    在调用方 ensure_scapy 的失败分支里做 (_offer_elevation_relaunch)。
    """
    if _npcap_installed():
        return True, "Npcap 已安装"
    if not _is_admin():
        return False, ("需要管理员权限才能安装 Npcap。请右键\"以管理员身份运行\"本程序后重试，"
                       "或手动下载安装: https://npcap.com/#download")
    url = "https://npcap.com/dist/npcap-1.80.exe"
    tmp = os.path.join(tempfile.gettempdir(), "npcap-install.exe")
    ok, msg = _download_file(url, tmp)
    if not ok:
        return False, f"{msg}\n可手动下载: https://npcap.com/#download"
    try:
        proc = subprocess.run([tmp, "/S"], capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            return False, f"Npcap 安装返回错误码 {proc.returncode}"
        return True, "Npcap 安装完成 (可能需要重启后生效)"
    except Exception as e:
        return False, f"Npcap 安装异常: {e}"


def _run_install_npcap_entry():
    """--install-npcap CLI 入口 (v1.9.7 PR-3): 装驱动 → 回菜单。

    自提权重启的落点: 管理员窗口里装完 Npcap 后不退出, 继续进交互菜单
    (提权窗口保持可用)。非管理员调用只提示不安装 (正常路径不会走到 —
    提议方会先 _offer_elevation_relaunch)。
    """
    if _npcap_installed():
        print(_c("  ✓ Npcap 已安装, 无需重复安装", C_GREEN))
        return
    if not _is_admin():
        print(_c("  ✘ --install-npcap 需要管理员权限 (请以管理员身份运行)", C_RED))
        return
    print(_c("  正在安装 Npcap 抓包驱动...", C_GRAY))
    ok, msg = _install_npcap()
    if ok:
        print(_c(f"  ✓ {msg}", C_GREEN))
    else:
        print(_c(f"  ✗ Npcap 安装失败: {msg.splitlines()[0]}", C_RED))


def _download_iperf3(target_dir=None):
    """下载 iperf3 Windows 二进制并解压到 target_dir。返回 (ok, path_or_msg)。

    target_dir: None 时优先选程序目录, 不可写则回退到 %LOCALAPPDATA%\\NetPulse\\。
    """
    # 选目标目录
    if target_dir is None:
        app_dir = os.path.dirname(os.path.abspath(
            sys.argv[0] if getattr(sys, "frozen", False) else __file__))
        try:
            test_file = os.path.join(app_dir, ".np_write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            target_dir = app_dir
        except Exception:
            target_dir = os.path.join(
                os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "NetPulse")
    os.makedirs(target_dir, exist_ok=True)
    dst = os.path.join(target_dir, "iperf3.exe")

    if os.path.exists(dst) and os.path.getsize(dst) > 1000:
        return True, dst

    # 候选下载源:
    # - ar51an/iperf3-win-builds (社区维护, 跟 esnet/iperf 同步发 Windows 预编译)
    # - ghproxy 国内镜像 (加速, 但偶尔 SSL 不稳, 失败自动回退)
    # 注: esnet/iperf 官方已不发布 Windows 二进制, 只发 .tar.gz 源码;
    #     历史 URL 形如 /esnet/iperf/releases/download/X/iperf-X-win64.zip 已 404。
    # 选 static-auth 版: 单文件无 cygwin1.dll 依赖, 部署干净; auth 默认不用, 行为同普通版
    IPERF3_VERSION = "3.21"
    IPERF3_WIN_REPO = "ar51an/iperf3-win-builds"  # Windows 预编译维护者
    zip_name = f"iperf-{IPERF3_VERSION}-win64-static-auth.zip"
    base_zip_url = f"https://github.com/{IPERF3_WIN_REPO}/releases/download/{IPERF3_VERSION}/{zip_name}"
    candidates = [
        base_zip_url,
        f"https://gh-proxy.com/{base_zip_url}",
    ]
    tmp_zip = os.path.join(tempfile.gettempdir(), zip_name)
    downloaded_from = None
    for url in candidates:
        print(_c(f"  尝试: {url[:80]}{'...' if len(url) > 80 else ''}", C_GRAY))
        ok, msg = _download_file(url, tmp_zip, timeout=120)
        if ok and os.path.exists(tmp_zip) and os.path.getsize(tmp_zip) > 10000:
            downloaded_from = url
            break
        print(_c(f"  ✗ {msg}", C_YELLOW))
    if not downloaded_from:
        return False, "所有 iperf3 下载源均失败"

    # 解压: 提取所有 .exe + .dll (防御 future zip 改名 / 多文件依赖如 cygwin1.dll)
    try:
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            extracted_iperf3 = False
            for info in zf.infolist():
                if info.is_dir():
                    continue
                fname = os.path.basename(info.filename).lower()
                # 只解 .exe / .dll 到目标目录 (扁平化, 不创建子目录)
                if not (fname.endswith(".exe") or fname.endswith(".dll")):
                    continue
                out_path = os.path.join(target_dir, os.path.basename(info.filename))
                with zf.open(info) as src, open(out_path, "wb") as f:
                    shutil.copyfileobj(src, f)
                if fname == "iperf3.exe":
                    extracted_iperf3 = True
            if not extracted_iperf3:
                return False, f"zip 内未找到 iperf3.exe (含 {len(zf.namelist())} 个文件)"
        try:
            os.remove(tmp_zip)
        except OSError:
            pass
    except Exception as e:
        return False, f"解压失败: {e}"

    if not os.path.exists(dst) or os.path.getsize(dst) < 1000:
        return False, f"解压后 iperf3.exe 不存在或过小: {dst}"
    return True, dst


# ── Ookla Speedtest CLI (speedtest.exe) 定位 ──
# 查找顺序: ./speedtest/speedtest.exe → 程序目录/speedtest/ → %LOCALAPPDATA%\NetPulse\speedtest\
#           → PATH (where speedtest)
# 打包模式 (frozen) 下 speedtest/ 子目录会被 PyInstaller --add-data 打入, 解压到临时目录
# _MEIPASS/speedtest/speedtest.exe, 需优先查 sys._MEIPASS。
def _find_ookla_speedtest():
    """查找 speedtest.exe (Ookla 官方 CLI)。返回 exe 绝对路径或 None。

    不交互式下载 (Ookla EULA 要求用户主动接受, 不适合自动下载; 缺失时返回 None,
    调用方降级跳过 Ookla 测速)。
    """
    global OOKLA_AVAILABLE
    exe_name = "speedtest.exe"

    # 1. PyInstaller 打包模式: 优先查 sys._MEIPASS (临时解压目录)
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        p = os.path.join(meipass, "speedtest", exe_name)
        if os.path.exists(p) and os.path.getsize(p) > 1000:
            OOKLA_AVAILABLE = True
            return p

    # 2. 当前工作目录的 speedtest/ 子目录
    p = os.path.join("speedtest", exe_name)
    if os.path.exists(p) and os.path.getsize(p) > 1000:
        OOKLA_AVAILABLE = True
        return os.path.abspath(p)

    # 3. 程序目录 (netpulse.py 或 EXE 所在目录) 的 speedtest/ 子目录
    app_dir = os.path.dirname(os.path.abspath(
        sys.argv[0] if getattr(sys, "frozen", False) else __file__))
    p = os.path.join(app_dir, "speedtest", exe_name)
    if os.path.exists(p) and os.path.getsize(p) > 1000:
        OOKLA_AVAILABLE = True
        return p

    # 4. %LOCALAPPDATA%\NetPulse\speedtest\ (用户手动放置的回退落点)
    fallback = os.path.join(
        os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
        "NetPulse", "speedtest", exe_name)
    if os.path.exists(fallback) and os.path.getsize(fallback) > 1000:
        OOKLA_AVAILABLE = True
        return fallback

    # 5. PATH 里的 speedtest (用户全局安装的情况)
    code, out, _ = run_cmd("where speedtest", timeout=5)
    if code == 0 and out.strip():
        candidate = out.strip().split("\n")[0].strip()
        if os.path.exists(candidate) and os.path.getsize(candidate) > 1000:
            OOKLA_AVAILABLE = True
            return candidate

    OOKLA_AVAILABLE = False
    return None


def _reload_scapy():
    """运行时重新导入 scapy 并绑定到模块命名空间。返回是否成功。

    v1.9.7 PR-2: 与启动预加载共用 _load_scapy (名字清单含 TCP/DNS,
    旧版手工列 globals 漏了这两个 — 安装重载路径与启动路径必须同源)。
    """
    return _load_scapy()


def ensure_scapy(auto_yes=False, mirror=None):
    """确保 scapy 可用: 缺失时提示用户, 确认后自动安装 (含 Npcap)。
    返回 True 表示可用, False 表示仍不可用。
      - 交互 TTY: 会询问用户是否安装
      - 非 TTY: 仅当 auto_yes=True (--install) 时才安装, 否则仅提示并降级
      - 网络环境: pip 镜像由 _resolve_pip_mirror() 自动选 (CLI/环境变量/国内探测/PyPI 默认)

    状态机 (与旧版的差异):
      旧版只用单个 ``SCAPY_OFFERED`` 标志, 拒绝后即便 CLI 加上 --install
      也不会重新提示, 语义错乱。新版区分 NEVER/DECLINED/ACCEPTED/INSTALLED,
      --install 总是能覆盖拒绝状态。
    """
    global SCAPY_OFFER_STATE
    # v1.9.7 PR-2: 先等后台预加载收尾 — 否则加载中途 SCAPY_AVAILABLE 仍为
    # False, 会被误判成「未安装」而走进安装询问
    _ensure_scapy()
    if FORCE_NO_SCAPY:
        return False
    if SCAPY_AVAILABLE:
        return True
    if SCAPY_OFFER_STATE == SCAPY_OFFER_STATE_DECLINED and not auto_yes:
        return False

    is_tty = sys.stdout.isatty()
    if not is_tty and not auto_yes:
        print(_c("  ⚠ scapy 未安装，DHCP 完整检测降级为仅检测当前 DHCP 服务器。", C_YELLOW))
        print(_c("    交互运行并选择安装，或加 --install 参数可启用完整检测。", C_GRAY))
        SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_DECLINED
        return False

    print()
    print(_c("  ┌──────────────────────────────────────────────────────────┐", C_YELLOW))
    print(_c("  │ scapy 未安装：DHCP 完整检测(发现多服务器干扰)需要它。    │", C_YELLOW))
    print(_c("  │ 完整检测还需 Npcap 抓包驱动 (Windows)。                  │", C_YELLOW))
    print(_c("  └──────────────────────────────────────────────────────────┘", C_YELLOW))

    if auto_yes:
        ans = "y"
    else:
        try:
            ans = input(_c("  是否现在自动安装 scapy (+Npcap)? [y/N] ", C_GREEN)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
    if ans not in ("y", "yes"):
        print(_c("  已跳过安装，DHCP 检测将降级运行。", C_GRAY))
        SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_DECLINED
        return False
    SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_ACCEPTED

    # 安装 scapy: 镜像由 _pip_install_scapy 内部自动选源
    print(_c("  正在安装 scapy (pip install scapy)...", C_GRAY))
    ok, msg = _pip_install_scapy(mirror=mirror)
    if not ok:
        print(_c("  ✗ scapy 安装失败:", C_RED))
        for line in msg.replace("\r", "").split("\n")[-12:]:
            if line.strip():
                print(_c("    " + line.strip(), C_GRAY))
        print(_c("    如需代理/镜像请设置 PIP_INDEX_URL 或加 --pip-mirror 重试。", C_GRAY))
        SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_DECLINED
        return False
    print(_c("  ✓ scapy 安装成功", C_GREEN))

    # 重新导入
    if not _reload_scapy():
        print(_c("  ✗ scapy 导入失败 (可能仍缺少 Npcap 或依赖)", C_RED))
        SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_DECLINED
        return False
    SCAPY_OFFER_STATE = SCAPY_OFFER_STATE_INSTALLED

    # Npcap (仅 Windows)
    if os.name == "nt":
        if _npcap_installed():
            print(_c("  ✓ Npcap 已安装", C_GREEN))
        else:
            print(_c("  正在准备安装 Npcap 抓包驱动...", C_GRAY))
            ok2, msg2 = _install_npcap()
            if ok2:
                print(_c("  ✓ " + msg2, C_GREEN))
            else:
                print(_c("  ⚠ Npcap: " + msg2, C_YELLOW))
                print(_c("    scapy 已装好，但二层收发仍需 Npcap 才能做完整 DHCP 检测。", C_GRAY))
                # v1.9.7 PR-3: 非管理员时提供一键提权重启 (装完 Npcap 回菜单),
                # 替代旧的「关闭 → 右键管理员运行」手工断档
                if not _is_admin():
                    _offer_elevation_relaunch(
                        ["--install-npcap"],
                        reason="安装 Npcap 抓包驱动需要管理员权限")

    return SCAPY_AVAILABLE


# ============================================================
# SECTION 2: CONSTANTS
# ============================================================

APP_NAME = "NetPulse"
APP_VERSION = "1.9.9"
# JSON 结果 Schema 版本 (对应 schema/netpulse-result-v{主.次}.json 文件)。
# 唯一来源 — build_report / --json-schema / debug-bundle 三处统一消费。
SCHEMA_VERSION = "1.2.0"
SCHEMA_FILENAME = f"netpulse-result-v{SCHEMA_VERSION.rsplit('.', 1)[0]}.json"


# 常用外网测试目标 (国内网络环境)
# 格式: (host, name, tcp_port)
#   tcp_port 用于 TCP 可达性预检 (应对 ICMP 被防火墙过滤的场景:
#   很多企业网禁 ping 到 8.8.8.8 / 114.114.114.114 等公共 DNS 或国际
#   站点, 但这些目标的 TCP 服务端口通常是开的, 不应该判为不可达)
# 目标选择: 以 Web 类目标为主 (TCP 80/443 更稳定), DNS 类为辅
# (DNS 服务器 ICMP 优先级低, 忙时会丢 ping, 不适合作为"外网丢包"的评估目标)
EXTERNAL_TARGETS = [
    ("www.baidu.com", "Baidu", 80),
    ("www.qq.com", "QQ", 80),
    ("223.5.5.5", "AliDNS", 53),
    ("www.taobao.com", "Taobao", 443),
]

# 常用 DNS 服务器 (国内网络环境)
DNS_SERVERS = [
    ("223.5.5.5", "AliDNS"),
    ("119.29.29.29", "DNSPod"),
    ("114.114.114.114", "114DNS"),
    ("180.76.76.76", "BaiduDNS"),
    ("1.2.4.8", "CNNIC SDNS"),
]

# Windows TCP 连接数限制参考值
TCP_LIMIT_WARN = 5000
TCP_LIMIT_CRITICAL = 10000


# ============================================================
# SECTION 3: UTILITY FUNCTIONS
# ============================================================

# 工作线程级 socket 缓存: 线程池内每个 worker 复用同一个 UDP socket,
# 避免每个 DNS 查询都创建/关闭 socket (~2-3ms × 20 次 ≈ 50ms)。
_DNS_SOCKET_TLS = threading.local()


def _get_dns_socket(timeout):
    """获取当前线程的 UDP socket (懒创建), 失败时新建。"""
    s = getattr(_DNS_SOCKET_TLS, "sock", None)
    if s is None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _DNS_SOCKET_TLS.sock = s
        except Exception:
            return None
    try:
        s.settimeout(timeout)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        _DNS_SOCKET_TLS.sock = None
        return None


def _dns_query(server, domain, timeout=2.5):
    """用 UDP 直接向指定 DNS 服务器查询域名 A 记录 (不依赖 nslookup 进程)。

    返回 (resolved_ip, elapsed_ms); 失败时 resolved_ip 为 None。
    并发安全, 可在线程池中使用 (worker 线程内复用 socket)。
    """
    try:
        tid = int.from_bytes(os.urandom(2), "big")
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1
        qname = (b"".join(bytes([len(p)]) + p.encode("ascii", "ignore")
                          for p in domain.split(".")) + b"\x00")
        question = qname + struct.pack(">HH", 1, 1)  # A 记录, IN
        s = _get_dns_socket(timeout)
        if s is None:
            return None, 0
        start = time.time()
        try:
            s.sendto(header + question, (server, 53))
            data, _ = s.recvfrom(4096)
            elapsed = round((time.time() - start) * 1000, 1)
            if len(data) < 12:
                return None, elapsed
            ancount = struct.unpack(">H", data[6:8])[0]
            off = 12 + len(question)
            ip = None
            for _ in range(ancount):
                # 跳过 name (可能为压缩指针)
                while off < len(data):
                    ln = data[off]
                    if ln & 0xC0 == 0xC0:
                        off += 2
                        break
                    off += 1
                    if ln == 0:
                        break
                    off += ln
                if off + 10 > len(data):
                    break
                rtype, _rclass, _ttl, rdlen = struct.unpack(
                    ">HHIH", data[off:off + 10])
                off += 10
                if rtype == 1 and rdlen == 4 and off + 4 <= len(data):
                    ip = socket.inet_ntoa(data[off:off + 4])
                    break
                off += rdlen
            return ip, elapsed
        except socket.timeout:
            return None, round((time.time() - start) * 1000, 1)
        except Exception:
            return None, round((time.time() - start) * 1000, 1)
    except Exception:
        return None, 0


# 命令结果 TTL 缓存: 同一次诊断会话内, 多个模块常跑同一条命令 (arp -a / ipconfig /
# route print / Get-NetAdapter 等), 缓存避免重复进程启动开销 (PowerShell 0.5-1s,
# 普通命令 50-200ms)。TTL 设短避免跨诊断的状态污染。
_CMD_CACHE = {}
_CMD_CACHE_TTL = 5.0  # 秒


# ============================================================
# 测速辅助: TCP ping / 延迟采样 / 国内节点选择 / 多连接上传
# ============================================================

def _tcping_ms(host_port, timeout=3.0):
    """TCP 握手测延迟 (毫秒)。host_port 形如 '1.2.3.4:8080' 或 '1.2.3.4'。"""
    host, _, port = host_port.rpartition(":")
    if not port or not port.isdigit():
        host, port = host_port, "80"
    try:
        t0 = time.perf_counter()
        s = socket.create_connection((host, int(port)), timeout=timeout)
        lat = (time.perf_counter() - t0) * 1000
        s.close()
        return round(lat, 1)
    except Exception:
        return None


class LatencyMonitor:
    """后台持续 ping 目标主机, 逐行解析 RTT, 供测速期间采样延迟变化。

    用 ``ping -t`` 流式输出 (Windows), 每个样本约 1s 间隔。测速的
    bufferbloat 联动: 空闲基线 → 下行负载 → 上行负载 各取一段样本。
    盯障模式 (MonitorSession) 复用本类并额外消费丢包流 (_loss_events)。

    历史坑: 中文 Windows 的 ping 输出是 "字节=32 时间=25ms" (GBK), 不含
    ASCII "time" — 旧正则在中文系统上从未采到过样本 (bufferbloat 静默
    降级为 —)。parse_ping_output 早就是双语的, 这里补齐。
    """

    # 超时/失败行 (双语): 盯障模式的丢包判定就靠这些
    _LOSS_RE = re.compile(
        r"请求超时|timed out|无法访问|unreachable|一般故障|general failure|"
        r"传输失败|transmit failed|找不到主机|could not find host", re.I)

    def __init__(self, target):
        self.target = target
        self._samples = []          # [(timestamp, rtt_ms)] 仅成功样本
        self._loss_events = []      # [timestamp] 丢包/超时时刻 (独立存放,
                                    #  不进 _samples — median_rtt/series_since
                                    #  的调用方 (测速) 假设样本全是数值)
        self._last_line_ts = None   # 最近一行输出时间 (ping 卡死/睡眠检测)
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        try:
            self._proc = subprocess.Popen(
                ["ping", "-t", "-w", "2000", self.target],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="gbk", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            return False
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        return True

    def _read_loop(self):
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                now = time.time()
                self._last_line_ts = now
                m = re.search(r"(?:time|时间)[=<]\s*([\d.]+)\s*ms", line, re.I)
                if m:
                    try:
                        rtt = float(m.group(1))
                    except ValueError:
                        continue
                    with self._lock:
                        self._samples.append((now, rtt))
                elif self._LOSS_RE.search(line):
                    with self._lock:
                        self._loss_events.append(now)
        except Exception:
            pass

    def wait_samples(self, count, timeout=6.0):
        """等待收集到至少 count 个样本, 返回这些样本的 rtt 列表 (按时间序)。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self._samples) >= count:
                    break
            time.sleep(0.1)
        with self._lock:
            return [s[1] for s in self._samples[-count:]]

    def median_rtt(self, since=None):
        """返回自 since (时间戳) 以来的样本中位数 rtt; 无样本返回 None。"""
        with self._lock:
            vals = [s[1] for s in self._samples if since is None or s[0] >= since]
        if not vals:
            return None
        vals = sorted(vals)
        n = len(vals)
        return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0

    def series_since(self, since):
        """返回自 since 以来的 [(t_off, rtt)] 时间序列 (相对 since 的秒数)。"""
        with self._lock:
            return [(round(s[0] - since, 1), s[1])
                    for s in self._samples if s[0] >= since]

    # ── 盯障模式新增的只读访问器 (测速路径不使用) ──
    def losses_since(self, since=None):
        """返回自 since 以来的丢包时刻列表 [timestamp]。"""
        with self._lock:
            return [t for t in self._loss_events if since is None or t >= since]

    def stream_since(self, since=None):
        """返回归并排序的完整流 [("ok", t, rtt) | ("loss", t, None)]。

        事件检测用: 成功与丢包按时间交织, 才能判定"连续丢包段"与恢复时刻。
        """
        with self._lock:
            merged = ([("ok", s[0], s[1]) for s in self._samples
                       if since is None or s[0] >= since]
                      + [("loss", t, None) for t in self._loss_events
                         if since is None or t >= since])
        merged.sort(key=lambda x: x[1])
        return merged

    def alive(self):
        """ping 进程是否仍在运行。"""
        return bool(self._proc) and self._proc.poll() is None

    def last_line_age(self):
        """距最近一行输出的秒数; 从无输出返回 None (ping 卡死/系统睡眠检测)。"""
        return None if self._last_line_ts is None else time.time() - self._last_line_ts

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass


# 运营商宽带常用档位 (Mbps) — 预估带宽就近取整用
BANDWIDTH_TIERS = [30, 50, 100, 200, 300, 500, 1000, 2000, 3000]


def estimate_bandwidth(download_mbps, upload_mbps=None):
    """由实测速率预估签约宽带带宽档位 (Mbps)。

    思路 (市面测速软件口径): 实测值通常比签约值低 5-15% (协议开销/服务器
    瓶颈), 乘 1.1 修正后向上就近取运营商档位; 上行做交叉校验提示非对称。
    返回 dict 或 None (无有效下行数据时)。
    """
    if not download_mbps or download_mbps <= 0:
        return None
    adj = download_mbps * 1.1
    tier = next((t for t in BANDWIDTH_TIERS if adj <= t), None)
    if tier is None:
        tier = BANDWIDTH_TIERS[-1]
    result = {
        "tier_mbps": tier,
        "text": f"约 {tier} 兆",
        "basis_download_mbps": round(download_mbps, 1),
        "adjusted_mbps": round(adj, 1),
    }
    # 上行交叉校验: 家宽常见非对称比例 5:1 ~ 20:1; 上行异常低时给出提示
    if upload_mbps and upload_mbps > 0:
        ratio = download_mbps / upload_mbps
        if ratio > 20:
            result["note"] = ("上下行比例悬殊 ({:.0f}:1), 符合家宽非对称套餐特征; "
                              "若办理的是对称专线请检查上行链路".format(ratio))
        elif ratio < 1.5:
            result["note"] = "上下行接近对称, 符合专线/政企宽带特征"
    return result


def bufferbloat_grade(idle_rtt, loaded_rtt):
    """由空闲/负载延迟计算 Bufferbloat 评级 (口径与 BufferbloatTester 一致)。

    返回 (grade_text, bloat_ms)。
    """
    if idle_rtt is None or loaded_rtt is None:
        return "无法判定 (延迟数据不足)", None
    bloat = loaded_rtt - idle_rtt
    if bloat < 5:
        return "A (优秀, 无缓冲膨胀)", bloat
    if bloat < 30:
        return "B (良好)", bloat
    if bloat < 60:
        return "C (一般)", bloat
    if bloat < 100:
        return "D (较差)", bloat
    return "F (很差, 负载下延迟飙升)", bloat


# 国内运营商官方测速节点 (speedtest 协议, host:port, 路径 /upload.php)
# 来源: 电信/联通/移动公开测速服务, 长期稳定; 运行时按 TCP 握手延迟选优。
# 内置列表 = 上行测速零第三方依赖, 不依赖 Ookla 动态列表 (该接口常被限流/403,
# 且代理环境下会选到海外节点导致结果严重偏低)。
DOMESTIC_SPEEDTEST_NODES = [
    # 中国电信
    ("电信", "speedtest1.online.sh.cn:8080"),            # 上海电信
    ("电信", "speedtest2.online.sh.cn:8080"),            # 上海电信 2
    ("电信", "tjrate.tjtele.com:8080"),                  # 天津电信
    ("电信", "5gnanjing.speedtest.jsinfo.net:8080"),     # 江苏电信 5G
    # 中国联通
    ("联通", "5g.shunicomtest.com:8080"),                # 上海联通
    ("联通", "speedtest1.gd165.com:8080"),               # 广东联通
    ("联通", "speedtest2.gd165.com:8080"),               # 广东联通 2
    ("联通", "speedtest02.js165.com:8080"),              # 江苏联通
    # 中国移动
    ("移动", "speedtest.bmcc.com.cn:8080"),              # 北京移动
    ("移动", "speedtest1.js.chinamobile.com:8080"),      # 江苏移动
    ("移动", "speedtest2.js.chinamobile.com:8080"),      # 江苏移动 2
    ("移动", "speedtest.zjmobile.com:8080"),             # 浙江移动
]


def _select_domestic_speedtest_server(callback=None):
    """从内置国内运营商节点列表挑选延迟最低的节点 (不依赖外部列表服务)。

    运营商顺序 (电信/联通/移动) 优先, 再按 TCP 握手延迟排序, 返回延迟最低者。
    返回 (server_dict, None) 或 (None, 错误信息)。
    """
    best, best_lat = None, None
    for isp, host in DOMESTIC_SPEEDTEST_NODES:
        lat = _tcping_ms(host, timeout=2.5)
        if lat is None:
            continue
        if callback:
            callback(f"  节点 中国{isp} ({host}) {lat:.0f}ms")
        if best is None or lat < best_lat:
            best = {"host": host, "sponsor": f"中国{isp}", "cc": "CN",
                    "country": "中国", "isp": isp}
            best_lat = lat
    if best is None:
        return None, "国内测速节点均不可达 (网络不通或服务器离线)"
    return best, None


def _upload_speed_multi(host_port, threads=4, duration=8.0, chunk_size=256 * 1024,
                        on_sample=None, series=None):
    """多连接 HTTP POST 上传测速 (speedtest 协议, 参考 speedtest-cli 做法)。

    向测速服务器 /upload.php 持续 POST 数据: 声明 100MB Content-Length,
    客户端持续 send, 达到 duration 后断开。多连接并发才能打满高速上行的
    拥塞窗口。每 0.2s 采样一次累计字节 → 瞬时速率 (实时动画 + 时间序列)。

    返回 dict (upload_mbps / uploaded_bytes / uploaded_mb / elapsed_s /
    threads / server) 或 None。
    """
    host, _, port = host_port.rpartition(":")
    if not port or not port.isdigit():
        host, port = host_port, "8080"
    port = int(port)

    total_uploaded = [0]
    bytes_lock = threading.Lock()
    errors = [0]

    def worker():
        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=20)
            conn.putrequest("POST", "/upload.php")
            conn.putheader("Content-Length", "104857600")   # 声明 100MB
            conn.putheader("User-Agent", "NetPulse/1.0")
            conn.endheaders()
            payload = os.urandom(chunk_size)
            deadline = time.time() + duration
            while time.time() < deadline:
                conn.send(payload)
                with bytes_lock:
                    total_uploaded[0] += len(payload)
        except Exception:
            with bytes_lock:
                errors[0] += 1
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    start = time.time()
    for t in ts:
        t.start()

    # 采样线程: 每 0.2s 读累计字节, 计算瞬时速率
    # 采样窗口固定为 duration: 不追踪线程退出 (打满带宽时 send 可能阻塞导致
    # 线程延迟退出, 追踪会采到尾部速率下降/掉 0 的假象)
    last_bytes, last_t = 0, start
    while time.time() < start + duration:
        time.sleep(0.2)
        if errors[0] >= threads:
            break
        now = time.time()
        with bytes_lock:
            cur = total_uploaded[0]
        dt = now - last_t
        if dt > 0:
            inst = (cur - last_bytes) * 8 / 1e6 / dt
            if on_sample:
                on_sample(inst, now - start, cur)
            if series is not None:
                series.append((round(now - start, 2), round(inst, 2)))
        last_bytes, last_t = cur, now

    for t in ts:
        t.join(timeout=5)
    elapsed = time.time() - start
    total = total_uploaded[0]
    if total <= 0:
        return None
    speed_mbps = total * 8 / 1e6 / elapsed
    return {
        "upload_mbps": round(speed_mbps, 2),
        "uploaded_bytes": total,
        "uploaded_mb": round(total / 1e6, 2),
        "elapsed_s": round(elapsed, 2),
        "threads": threads,
        "server": host_port,
    }


def _download_speed_test(url, target_bytes=5 * 1024 * 1024, chunk_size=64 * 1024,
                         overall_timeout=20, callback=None, connect_timeout=10,
                         chunk_cb=None, max_duration=None):
    """下载测速通用函数: chunked read, 达到 max_duration 时长或 target_bytes 字节就停。

    与 ``resp.read()`` 一次读完的区别:
      - 旧版 resp.read() 必须等服务器发完全部数据, 10MB 文件在 1Mbps 链路
        需要 80s, 国际 CDN 从国内访问 5-10 分钟
      - 新版到时长 (max_duration) 或字节量 (target_bytes) 就 break 退出

    参数:
      url: 测速源 URL
      target_bytes: 字节上限, 累计下载到这么多字节就停 (默认 5MB; 测速时作为
                    "最多下载量" 防止千兆链路无上限拉取)
      chunk_size: 每次 read 的块大小 (默认 64KB)
      overall_timeout: 数据传输阶段兜底超时秒数 (默认 20s, 超过就 break 用
                       已下载数据; 连接/TLS 握手不计入)
      max_duration: 目标测速时长 (秒)。给定后测速窗口 = 该时长 (而非字节数),
                    保证速率曲线足够长、能反映稳定性; None = 仅按字节停
                    (向后兼容)
      callback: 进度回调, 接受 str (每 1MB 或每 1s 报一次)
      connect_timeout: 连接 + TLS 握手 + 响应头超时 (默认 10s)
      chunk_cb: 每读一块字节数的回调 (实时采样用)

    返回 dict (含 download_mbps / downloaded_bytes / downloaded_mb / elapsed_s)
    或 None (失败)。计时从收到第一个数据字节开始, 排除 TCP/TLS/HTTP 头开销,
    避免高速链路上握手耗时压低测速均值。
    """
    try:
        req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
        # 连接 + TLS 握手 + 响应头: 不计入测速窗口 (单独超时)
        resp = urlopen(req, timeout=connect_timeout)
        start = time.time()          # 首个数据字节到达, 测速窗口从这里开始
        # 测速窗口: max_duration 优先 (固定时长测速), 否则 overall_timeout 兜底
        deadline = start + (max_duration if max_duration else overall_timeout)
        downloaded = 0
        last_report_time = start
        last_report_bytes = 0
        while True:
            now = time.time()
            if now >= deadline:
                break
            # 每次 read 的 timeout = 剩余时间, 至少 2s 避免频繁超时
            remaining = max(2.0, deadline - now)
            try:
                chunk = resp.read(chunk_size)
            except (socket.timeout, TimeoutError):
                break  # 单次 read 超时, 用已下数据计算
            if not chunk:
                break  # EOF
            downloaded += len(chunk)
            if chunk_cb:
                chunk_cb(len(chunk))
            # 进度 callback: 每 1MB 或每 1s 报一次
            if callback and (downloaded - last_report_bytes >= 1024 * 1024
                             or now - last_report_time >= 1.0):
                cur_speed = (downloaded * 8) / 1e6 / (now - start)
                callback(f"  已下 {downloaded // 1024}KB, 当前 {cur_speed:.2f} Mbps")
                last_report_time = now
                last_report_bytes = downloaded
            if downloaded >= target_bytes:
                break
        elapsed = time.time() - start
        if downloaded > 0:
            speed_mbps = (downloaded * 8) / 1e6 / elapsed
            return {
                "url": url,
                "download_mbps": round(speed_mbps, 2),
                "downloaded_bytes": downloaded,
                "downloaded_mb": round(downloaded / 1e6, 2),
                "elapsed_s": round(elapsed, 2),
            }
        return None
    except Exception as e:
        if callback:
            callback(f"  测速失败 ({url[:40]}...): {e}")
        return None


def _download_speed_multi(url, threads=4, target_bytes=5 * 1024 * 1024,
                          chunk_size=64 * 1024, overall_timeout=20,
                          connect_timeout=10, on_sample=None, series=None,
                          max_duration=None):
    """多连接下载测速: 对同一 URL 并发开 threads 个连接, 达到 max_duration 时长
    或 target_bytes 字节后各自停止。

    为什么需要多连接:
      - 单 TCP 连接吞吐受拥塞窗口/RTT 限制, 300M+ 宽带下打不满
      - 多连接 (类似浏览器/迅雷) 才能逼近真实可用带宽; 国内镜像对并发连接
        支持良好, 本机实测 4 连接可把 100M 链路利用率拉到 90%+ (单连接只有
        约 65%)

    聚合方式: 总字节 = 各连接之和; 耗时 = 各连接中最长的数据传输耗时 (每个
    连接计时均从各自首字节开始, 已排除握手); 速率 = 总字节 * 8 / 1e6 / 耗时。

    max_duration: 目标测速时长 (秒), 透传给每个连接; 测速窗口由时长决定,
    保证速率曲线足够长 (快链路也不提前停)。

    on_sample: 实时采样回调 (instant_mbps, elapsed_s, cumulative_bytes), 每
    0.2s 一次, 供终端实时动画; series: 追加 (t_off, mbps) 采样点到列表。

    返回 dict (含 download_mbps / downloaded_bytes / downloaded_mb / elapsed_s
    / threads / url) 或 None (全部连接失败)。
    """
    results = []
    results_lock = threading.Lock()
    bytes_lock = threading.Lock()
    total_bytes = [0]

    def worker():
        def _chunk_cb(n):
            with bytes_lock:
                total_bytes[0] += n
        r = _download_speed_test(
            url, target_bytes=target_bytes, chunk_size=chunk_size,
            overall_timeout=overall_timeout, callback=None,
            connect_timeout=connect_timeout, chunk_cb=_chunk_cb,
            max_duration=max_duration)
        if r and r.get("downloaded_bytes", 0) > 0:
            with results_lock:
                results.append(r)

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    start = time.time()
    for t in ts:
        t.start()

    # 采样线程: 每 0.2s 读累计字节, 计算瞬时速率
    last_bytes, last_t = 0, start
    while time.time() < start + overall_timeout + 2:
        time.sleep(0.2)
        if not any(t.is_alive() for t in ts):
            break
        now = time.time()
        with bytes_lock:
            cur = total_bytes[0]
        dt = now - last_t
        if dt > 0:
            inst = (cur - last_bytes) * 8 / 1e6 / dt
            if on_sample:
                on_sample(inst, now - start, cur)
            if series is not None:
                series.append((round(now - start, 2), round(inst, 2)))
        last_bytes, last_t = cur, now

    for t in ts:
        t.join()

    if not results:
        return None
    total_bytes_v = sum(r["downloaded_bytes"] for r in results)
    elapsed = max(r["elapsed_s"] for r in results)
    if elapsed <= 0:
        return None
    speed_mbps = (total_bytes_v * 8) / 1e6 / elapsed
    return {
        "url": url,
        "download_mbps": round(speed_mbps, 2),
        "downloaded_bytes": total_bytes_v,
        "downloaded_mb": round(total_bytes_v / 1e6, 2),
        "elapsed_s": round(elapsed, 2),
        "threads": threads,
    }


def _tcp_probe(host, port=80, timeout=2.0):
    """TCP 可达性预检: 给定 host:port 测能否完成 TCP 三次握手。

    返回 (reachable: bool, rtt_ms: float | None):
      - reachable: 是否能 connect 成功
      - rtt_ms: 三次握手耗时 (毫秒), 失败时 None

    与 ping 的关系:
      - ping 通 + TCP 通 = 目标完全可达
      - ping 100% 丢 + TCP 通 = ICMP 被防火墙过滤 ("禁拼"), 目标实际可达
      - ping 100% 丢 + TCP 不通 = 目标不可达 (网络问题或主机宕机)

    实现用 socket.create_connection (内部一步完成 getaddrinfo + create +
    connect), 计时只覆盖真正的 TCP 握手时间, 不含 DNS 解析。
    """
    try:
        t0 = time.perf_counter()
        s = socket.create_connection((host, port), timeout=timeout)
        rtt = round((time.perf_counter() - t0) * 1000, 1)
        s.close()
        return True, rtt
    except Exception:
        return False, None


def _tcp_probe_multi(host, ports=(80, 443, 53), timeout=2.0):
    """对 host 试多个端口, 任一通就算 TCP 可达。

    为什么需要这个: 不同服务的常用端口不一定都开:
      - DNS 119.29.29.29 只开 UDP 53, TCP 53 经常被禁
      - Web 服务大多数开 80/443
      - Cloudflare 1.1.1.1 只在特定端口开 DNS-over-TLS (853) / HTTPS (443)
    所以单一端口探测会误判, 试多个端口任一通就算可达。
    """
    for port in ports:
        ok, rtt = _tcp_probe(host, port=port, timeout=timeout)
        if ok:
            return True, rtt, port
    return False, None, None


def run_cmd(cmd, timeout=30, shell=True, use_cache=True):
    """执行系统命令, 返回 (returncode, stdout, stderr)。

    性能:
      - 透明 TTL 缓存: 同一 (cmd, timeout) 在 5 秒内直接返回缓存。
        跨模块重复调用 (如 arp -a 被 4 个模块各调一次) 实际只跑一次。
      - 缓存 key 含 timeout: 不同 timeout 的结果不混用, 避免超时被杀
        的半截输出被后续正常 timeout 调用误用。
      - use_cache=False 可强制重跑 (例如 _pip_install_scapy 这类带副作用的)。

    编码处理 (与 P1#7 一致):
      - 按「系统 ANSI codepage → gbk → utf-8」顺序, 首次成功编码缓存。
    """
    cache_key = (cmd, timeout) if use_cache else None
    if cache_key is not None:
        cached = _CMD_CACHE.get(cache_key)
        if cached is not None:
            age = time.time() - cached[0]
            if age < _CMD_CACHE_TTL:
                return cached[1], cached[2], cached[3]
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, timeout=timeout
        )
        stdout = result.stdout
        stderr = result.stderr
        # 编码缓存按 cmd 维度 (不同命令互不污染)
        cache_cmd = cmd if isinstance(cmd, str) else None
        stdout_str, stderr_str = _decode_bytes_pair(cache_cmd, stdout, stderr)
        rc, so, se = result.returncode, stdout_str, stderr_str
    except subprocess.TimeoutExpired:
        rc, so, se = -1, "", "命令执行超时"
    except Exception as e:
        rc, so, se = -1, "", str(e)
    if cache_key is not None:
        _CMD_CACHE[cache_key] = (time.time(), rc, so, se)
    return rc, so, se


# 编码缓存: 按 cmd 维度分别记命中编码, 避免不同命令互相污染。
# 例如 arp -a 在中文 Windows 上 cp936 成功, netsh 在 Win11 22H2+ 输出 utf-8,
# 全局单一缓存会把后者强行按 cp936 解码产生乱码。
_DECODE_CACHE = {}  # cmd -> encoding name (e.g. "cp936", "utf-8", "utf-8-replace")


def _system_ansi_codepage():
    """获取 Windows ANSI 代码页 (e.g. 936=GBK, 1252=Western), 失败返回 None。"""
    if os.name != "nt":
        return None
    try:
        import ctypes
        return "cp" + str(ctypes.windll.kernel32.GetACP())
    except Exception:
        return None


def _build_decode_order():
    """构造编码尝试顺序: ANSI codepage > GBK > UTF-8 (去重保序)。"""
    seen = set()
    order = []
    for enc in (_system_ansi_codepage(), "gbk", "utf-8"):
        if enc and enc not in seen:
            seen.add(enc)
            order.append(enc)
    if not order:
        order = ["utf-8"]
    return order


def _decode_bytes_pair(cmd, stdout, stderr):
    """按 cmd 维度缓存的编码选择: 同一命令的首次成功编码记下来, 后续直接用;
    不同命令独立缓存, 避免 arp (cp936) 污染 netsh (utf-8)。

    若该命令上次缓存的编码本轮失败, 自动回退到通用尝试序列并重写缓存。
    全部失败时 errors='replace' 保底。
    """
    if not stdout and not stderr:
        return "", ""

    # 1) 优先用本命令上次成功的编码
    if cmd:
        cached = _DECODE_CACHE.get(cmd)
        if cached and cached != "utf-8-replace":
            try:
                so = stdout.decode(cached) if stdout else ""
                se = stderr.decode(cached) if stderr else ""
                return so, se
            except (UnicodeDecodeError, AttributeError):
                pass  # 本轮输出与上次不同, 回退到通用序列

    # 2) 通用尝试序列
    for enc in _build_decode_order():
        try:
            so = stdout.decode(enc) if stdout else ""
            se = stderr.decode(enc) if stderr else ""
            if cmd:
                _DECODE_CACHE[cmd] = enc
            return so, se
        except (UnicodeDecodeError, AttributeError):
            continue

    # 3) 全部失败: errors='replace' 保底
    so = stdout.decode("utf-8", errors="replace") if stdout else ""
    se = stderr.decode("utf-8", errors="replace") if stderr else ""
    if cmd:
        _DECODE_CACHE[cmd] = "utf-8-replace"
    return so, se


def run_ps(script, timeout=30):
    """执行 PowerShell 脚本"""
    cmd = f'powershell -NoProfile -Command "{script}"'
    return run_cmd(cmd, timeout=timeout)


def _get_local_ip_independent():
    """不依赖 get_default_gateway 的本机 IP 获取 (用于打破循环依赖)。

    UDP socket connect() 不真正发包, 只在路由表里查"到 223.5.5.5 走哪张网卡",
    返回该网卡的源 IP。这是当前会话内最稳定的本机 IP 来源, 不受 VPN /
    虚拟网卡默认路由顺序影响 (split-tunnel VPN 不会接管本机 IP)。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return None


def _pick_best_gateway(candidates, local_ip=None):
    """从多个默认网关候选中选最合适的。

    优先级:
      1. 与 local_ip 在同一子网 (用 _get_local_subnet 拿真实 prefix length,
         避免 /24 硬编码在大子网环境误判 — 这跟 P0#3 是同一类问题)
      2. 第一个候选 (保留旧行为兜底)

    candidates: 网关 IP 列表 (IPv4 字符串)
    local_ip: 本机 IP; None 时自动用 _get_local_ip_independent 拿
    返回: 选中的网关 IP, 或 None
    """
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    if local_ip is None:
        local_ip = _get_local_ip_independent()
    if not local_ip:
        return candidates[0]
    local_net = _get_local_subnet(local_ip)
    if local_net is not None:
        for gw in candidates:
            try:
                if ipaddress.IPv4Address(gw) in local_net:
                    return gw
            except Exception:
                continue
    return candidates[0]


def get_default_gateway():
    """获取默认网关 IP。

    优先级:
      1. 从 ``route print 0.0.0.0`` 收集所有 0.0.0.0 默认路由, 用
         _pick_best_gateway 选与本机 IP 同子网的 (避免 VPN/虚拟适配器干扰)
      2. Fallback: WMI Win32_NetworkAdapterConfiguration.DefaultIPGateway,
         同样多候选时按子网优先选
    """
    # 1) route print
    code, out, _ = run_cmd("route print 0.0.0.0")
    candidates = []
    for line in out.split("\n"):
        parts = line.split()
        # 完整字段: dest, mask, gateway, interface, metric
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            try:
                ipaddress.IPv4Address(parts[2])
                candidates.append(parts[2])
            except Exception:
                continue
    picked = _pick_best_gateway(candidates)
    if picked:
        return picked

    # 2) WMI fallback
    code, out, _ = run_ps(
        "(Get-WmiObject Win32_NetworkAdapterConfiguration "
        "-Filter 'IPEnabled=True').DefaultIPGateway"
    )
    # WMI 输出可能是:
    #   {100.70.0.1}          (单适配器)
    #   {100.70.0.1}
    #   {25.255.255.254}      (多适配器, 每行一对花括号)
    wmi_candidates = []
    for line in (out or "").strip().split("\n"):
        gw = line.strip().strip('"').strip("{").strip("}").strip()
        if not gw:
            continue
        try:
            ipaddress.IPv4Address(gw)
            wmi_candidates.append(gw)
        except Exception:
            continue
    return _pick_best_gateway(wmi_candidates)


def get_local_ip():
    """获取本机 IP 地址 (优先返回与网关同子网的物理网卡 IP)。

    实现策略:
      - 优先用 UDP socket 拿到「主用」本机 IP (不依赖 gateway, 避免循环)
      - 再用 _get_local_subnet (真实 prefix length) 验证与网关是否同子网
      - 若主用 IP 与网关不同子网, 扫描 ipconfig 找与网关同子网的 IP
        (可能存在于多网卡, 但被低 metric 路由藏起来)
    """
    # 方法1: UDP socket (主用本机 IP, 不依赖 get_default_gateway)
    primary_ip = _get_local_ip_independent()

    # 方法2: 通过 ipconfig 找与网关同子网的 IP (用真实 prefix length, 不用 /24)
    gateway = get_default_gateway()
    if gateway:
        try:
            gw_addr = ipaddress.IPv4Address(gateway)
            code, out, _ = run_cmd("ipconfig")
            for line in out.split("\n"):
                line = line.strip()
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if not m:
                    continue
                if not ("IPv4" in line or "IP Address" in line or "IP 地址" in line):
                    continue
                ip = m.group(1)
                if ip.startswith("127."):
                    continue
                try:
                    ip_addr = ipaddress.IPv4Address(ip)
                except Exception:
                    continue
                # 优先: 与本机主用 IP 同一 /32 (就是它本身)
                if primary_ip and ip == primary_ip:
                    return ip
                # 次选: 与网关同一子网 (用 _get_local_subnet 拿真实 mask)
                ip_net = _get_local_subnet(ip)
                if ip_net is not None and gw_addr in ip_net:
                    return ip
        except Exception:
            pass

    if primary_ip:
        return primary_ip

    # 方法3: PowerShell
    code, out, _ = run_ps(
        "(Get-WmiObject Win32_NetworkAdapterConfiguration "
        "-Filter 'IPEnabled=True').IPAddress"
    )
    if out:
        for line in out.strip().split("\n"):
            line = line.strip().strip('"').strip("{").strip("}")
            if line and not line.startswith("127.") and "." in line:
                return line
    return "127.0.0.1"


def get_dns_servers():
    """获取系统配置的 DNS 服务器"""
    code, out, _ = run_cmd("ipconfig /all")
    dns_servers = []
    for line in out.split("\n"):
        if "DNS Servers" in line or "DNS 服务器" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ip = parts[1].strip()
                try:
                    ipaddress.IPv4Address(ip)
                    if ip not in dns_servers:
                        dns_servers.append(ip)
                except Exception:
                    pass
    return dns_servers


# 本机 IP -> 真实子网的缓存 (PowerShell Get-NetIPAddress 查询较慢, 一次会话内复用)
_LOCAL_SUBNET_CACHE = {}


def _get_local_subnet(local_ip):
    """根据本机 IP 解析其所属的 IPv4 子网, 含真实 prefix length。

    返回 ``ipaddress.IPv4Network``, 失败时回退 ``/24`` (兼容老行为)。
    缓存结果避免重复查询 (一次诊断会话内本机 IP 不变)。
    """
    if local_ip in _LOCAL_SUBNET_CACHE:
        return _LOCAL_SUBNET_CACHE[local_ip]
    if not local_ip or local_ip == "127.0.0.1":
        return None
    try:
        ipaddress.IPv4Address(local_ip)  # 必须是合法 IPv4
    except Exception:
        return None
    # 用 PowerShell 取真实 prefix length (比解析 ipconfig 文本更稳)
    try:
        code, out, _ = run_ps(
            f"(Get-NetIPAddress -IPAddress '{local_ip}' -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | "
            "Select-Object -First 1 -ExpandProperty PrefixLength)")
        m = re.search(r"\b(\d+)\b", out or "")
        if m:
            prefix = int(m.group(1))
            if 0 <= prefix <= 32:
                net = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                _LOCAL_SUBNET_CACHE[local_ip] = net
                return net
    except Exception:
        pass
    # 回退: /24 (写缓存避免重复 powershell 调用, 本机 IP 在一次会话内不变)
    try:
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        _LOCAL_SUBNET_CACHE[local_ip] = net
        return net
    except Exception:
        return None


def get_public_ip():
    """获取公网 IPv4 (国内 + 国际服务池, 并发请求, 首个成功即返回)。

    服务池从 3 个扩到 6 个, 涵盖:
      - 国内 (百度/IPIP/Oray): 延迟低, 国内访问稳
      - 国际 (ip.sb / ifconfig.me / api.ipify.org): 出口链路国际访问异常时
        国内服务可能拿不到真实公网 IP, 用国际服务对比
    4s 单服务超时, 整体跑完不会超过 6s (并发)。
    """
    services = [
        # 国内
        ("https://qifu-api.baidubce.com/ip/local/geo/v1/district", "json"),
        ("https://myip.ipip.net", "text"),
        ("https://ddns.oray.com/checkip", "text"),
        # 国际
        ("https://api.ipify.org", "text"),
        ("https://ifconfig.me/ip", "text"),
        ("https://ip.sb", "text"),
    ]

    def _probe(url, mode):
        try:
            req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
            resp = urlopen(req, timeout=4)
            raw = resp.read().decode("utf-8", "ignore")
            if mode == "json":
                data = json.loads(raw)
                return (data.get("data") or {}).get("ip", "")
            m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw)
            return m.group(1) if m else ""
        except Exception:
            return ""

    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(_probe, u, m) for u, m in services]
        for f in as_completed(futs):
            ip = f.result()
            if ip:
                return ip
    return None


# IPv6 公网 IP 服务 (国内访问不稳, 失败容错)
_IPV6_SERVICES = [
    "https://api64.ipify.org",      # ipify IPv6 版, 国际稳定
    "https://ipv6.icanhazip.com",   # icanhazip IPv6 版
    "https://v6.ident.me",          # ident.me IPv6
]


def get_public_ipv6():
    """获取公网 IPv6 地址, 失败返回 None。

    国内运营商很多没开通 IPv6, 拿到 None 是正常结果 (不代表出错)。
    """
    def _probe(url):
        try:
            req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
            # 强制走 IPv6, 避免 happy eyeballs 退回 IPv4
            resp = urlopen(req, timeout=4)
            raw = resp.read().decode("utf-8", "ignore").strip()
            m = re.search(r"\b([0-9a-fA-F:]{3,})\b", raw)
            if m and ":" in m.group(1):
                # 简单合法性检查
                try:
                    ipaddress.IPv6Address(m.group(1))
                    return m.group(1)
                except Exception:
                    return None
            return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=3) as ex:
        for ip in ex.map(_probe, _IPV6_SERVICES):
            if ip:
                return ip
    return None


# IP 归属地查询 (ASN/地理位置), 拿公网 IP 后调用
# 用 ip-api.com (免费, 限速 45 req/min, HTTP, 支持 IPv6)
def get_ip_geo(ip):
    """查询 IP 的归属地 (国家/省/城市/ASN/运营商)。

    返回 dict 形如:
      {"country": "中国", "region": "浙江", "city": "杭州",
       "isp": "中国电信", "asn": "AS4134 Chinanet", "org": "Chinanet"}
    任何字段缺失时为空字符串。失败返回 None。
    """
    if not ip:
        return None
    try:
        # ip-api.com: lang=zh-CN 中文国家/省/市, fields=... 只取要用的
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp,org,as"
        req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
        resp = urlopen(req, timeout=6)
        raw = resp.read().decode("utf-8", "ignore")
        data = json.loads(raw)
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country", "") or "",
            "region":  data.get("regionName", "") or "",
            "city":    data.get("city", "") or "",
            "isp":     data.get("isp", "") or "",
            "org":     data.get("org", "") or "",
            "asn":     data.get("as", "") or "",
        }
    except Exception:
        return None


def parse_ping_output(output):
    """解析 ping 命令输出 (支持中文/英文 Windows)。

    兼容 Windows 7/部分多语版本把 "Packets: Sent / Received / Lost" 拆到
    多行的情况: 旧版用 ``.*?`` 不跨 \\n 匹配, 在跨行场景会丢字段。修复:
    解析统计行前先把 \\n 折成空格, 行为一致。
    """
    result = {"sent": 0, "received": 0, "loss_pct": 100.0,
              "min_ms": 0, "avg_ms": 0, "max_ms": 0, "rtts": [], "jitter_ms": 0,
              "ttl": None}
    # 解析回复行 - 匹配 "时间=2ms" / "time=2ms" / "时间<1ms" / "time<1ms"
    # 同时提取首个 TTL (Windows ping 每个回复行都带 TTL=xx)
    for line in output.split("\n"):
        # 先检查 <1ms 模式
        if re.search(r"(?:[Tt]ime|时间)<\s*1?\s*ms", line):
            result["rtts"].append(0)
        else:
            m = re.search(r"(?:[Tt]ime|时间)[=<]\s*(\d+)\s*ms", line)
            if m:
                result["rtts"].append(int(m.group(1)))
        # 提取首个 TTL (用于环路检测, 避免单独再 ping 一次)
        if result["ttl"] is None:
            tm = re.search(r"TTL[=:]\s*(\d+)", line, re.IGNORECASE)
            if tm:
                result["ttl"] = int(tm.group(1))
    # 把 "统计" 段折成单行, 兼容老 Windows 把字段拆到多行
    flat = re.sub(r"\s*\n\s*", " ", output)
    # 解析统计行
    m = re.search(
        r"(?:Sent|已发送)\s*[=:：]\s*(\d+)"
        r".*?(?:Received|已接收)\s*[=:：]\s*(\d+)"
        r".*?(?:Lost|丢失)\s*[=:：]\s*(\d+)\s*[\(（](\d+)%",
        flat
    )
    if m:
        result["sent"] = int(m.group(1))
        result["received"] = int(m.group(2))
        result["loss_pct"] = float(m.group(4))
    # 解析 RTT 统计
    m = re.search(
        r"(?:Min\S*|最短)\s*[=:：]\s*(\d+)\s*ms"
        r".*?(?:Max\S*|最长)\s*[=:：]\s*(\d+)\s*ms"
        r".*?(?:Average|平均)\s*[=:：]\s*(\d+)\s*ms",
        output
    )
    if m:
        result["min_ms"] = int(m.group(1))
        result["max_ms"] = int(m.group(2))
        result["avg_ms"] = int(m.group(3))
    elif result["rtts"]:
        result["min_ms"] = min(result["rtts"])
        result["max_ms"] = max(result["rtts"])
        result["avg_ms"] = round(sum(result["rtts"]) / len(result["rtts"]), 1)
    # 从 RTT 推断 sent/received (如果统计行未匹配)
    if result["sent"] == 0 and result["rtts"]:
        result["sent"] = len(result["rtts"])
        result["received"] = len(result["rtts"])
        result["loss_pct"] = 0.0
    # 计算抖动
    if len(result["rtts"]) >= 2:
        diffs = [abs(result["rtts"][i] - result["rtts"][i-1])
                 for i in range(1, len(result["rtts"]))]
        result["jitter_ms"] = round(sum(diffs) / len(diffs), 2)
    return result


def ping_host(host, count=20, packet_size=64, timeout=30, wait_ms=3000):
    """Ping 指定主机。

    timeout: 进程总超时 (秒) — 留足 count × wait + 启动开销, 避免 ping
             被外部 kill 导致 parse_ping_output 拿不到完整统计行。
    wait_ms: 单包超时 (毫秒) — 默认 3000 接近系统默认值 (-w 4000), 不要
             压得太低否则偶发 >1.5s 的回复会被 ping 判为"超时丢包",
             与手动 ping 结果对不上 (老版曾用 timeout*1000//count 推算
             wait, count=10 时仅 1500ms, 是误判丢包的根因)。
    """
    # 进程超时比理论最大值稍宽, 防 stdout 被截断造成 parse 失真
    proc_timeout = max(timeout, (count * wait_ms // 1000) + 10)
    cmd = f"ping -n {count} -l {packet_size} -w {wait_ms} {host}"
    code, out, _ = run_cmd(cmd, timeout=proc_timeout)
    return parse_ping_output(out)


def parse_tracert_output(output):
    """解析 tracert 命令输出"""
    hops = []
    current_hop = None
    for line in output.split("\n"):
        line = line.strip()
        # 匹配跳数
        m = re.match(r"^\s*(\d+)\s+(.*)", line)
        if m:
            hop_num = int(m.group(1))
            rest = m.group(2)
            # 提取 IP
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", rest)
            if not ip_match:
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            ip = ip_match.group(1) if ip_match else "*"
            # 提取 RTT
            rtts = re.findall(r"<\s*1\s*ms|(\d+)\s*ms", rest)
            hop_data = {
                "hop": hop_num,
                "ip": ip,
                "rtts": [],
                "avg_ms": 0,
                "timeout": ip == "*"
            }
            for r in rtts:
                if r == "< 1 ms" or r == "":
                    hop_data["rtts"].append(0)
                else:
                    try:
                        hop_data["rtts"].append(int(r))
                    except ValueError:
                        pass
            if hop_data["rtts"]:
                hop_data["avg_ms"] = round(sum(hop_data["rtts"]) / len(hop_data["rtts"]), 1)
            hops.append(hop_data)
    return hops


def get_process_name(pid):
    """根据 PID 获取进程名"""
    if pid == 0:
        return "System Idle"
    if pid == 4:
        return "System"
    code, out, _ = run_cmd(f'tasklist /FI "PID eq {pid}" /FO CSV /NH', timeout=5)
    if out:
        parts = out.strip().split('","')
        if len(parts) >= 1:
            name = parts[0].strip('"')
            if name and "INFO:" not in name:
                return name
    return f"PID:{pid}"


def format_speed(mbps):
    """格式化速率显示"""
    if mbps >= 1000:
        return f"{mbps/1000:.2f} Gbps"
    return f"{mbps:.1f} Mbps"


def get_network_adapters():
    """获取网络适配器信息"""
    adapters = []
    code, out, _ = run_ps(
        "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, "
        "LinkSpeed, MediaType, PhysicalMediaType | ConvertTo-Json"
    )
    if out and out.strip():
        try:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]
            for item in data:
                adapters.append({
                    "name": item.get("Name", ""),
                    "description": item.get("InterfaceDescription", ""),
                    "status": item.get("Status", ""),
                    "link_speed": item.get("LinkSpeed", ""),
                    "media_type": item.get("MediaType", ""),
                    "physical_media": item.get("PhysicalMediaType", ""),
                })
        except Exception:
            pass
    return adapters


def get_wifi_interfaces():
    """获取 WiFi 接口信息"""
    code, out, _ = run_cmd("netsh wlan show interfaces")
    return out


def get_wifi_networks():
    """获取可见的 WiFi 网络"""
    code, out, _ = run_cmd("netsh wlan show networks mode=bssid")
    networks = []
    current = {}
    current_bssid = {}
    for line in out.split("\n"):
        line_stripped = line.strip()
        # SSID
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", line_stripped)
        if m:
            if current_bssid:
                current.setdefault("bssids", []).append(current_bssid)
                current_bssid = {}
            if current:
                networks.append(current)
            current = {"ssid": m.group(1).strip(), "bssids": []}
            continue
        # BSSID
        m = re.match(r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", line_stripped)
        if m:
            if current_bssid:
                current.setdefault("bssids", []).append(current_bssid)
            current_bssid = {"bssid": m.group(1).strip()}
            continue
        # Signal
        m = re.match(r"信号\s*:\s*(\d+)%|Signal\s*:\s*(\d+)%", line_stripped)
        if m:
            sig = m.group(1) or m.group(2)
            if current_bssid is not None:
                current_bssid["signal"] = int(sig)
            continue
        # Channel (Radio type / Channel)
        m = re.match(r"频道\s*:\s*(\d+)|Channel\s*:\s*(\d+)", line_stripped)
        if m:
            ch = m.group(1) or m.group(2)
            if current_bssid is not None:
                current_bssid["channel"] = int(ch)
            continue
        # Authentication
        m = re.match(r"身份验证\s*:\s*(.*)|Authentication\s*:\s*(.*)", line_stripped)
        if m:
            auth = m.group(1) or m.group(2)
            if current_bssid is not None:
                current_bssid["auth"] = auth.strip()
            else:
                current["auth"] = auth.strip()
            continue
        # Encryption
        m = re.match(r"加密\s*:\s*(.*)|Encryption\s*:\s*(.*)", line_stripped)
        if m:
            enc = m.group(1) or m.group(2)
            current["encryption"] = enc.strip()
            continue
        # Radio type
        m = re.match(r"无线电类型\s*:\s*(.*)|Radio type\s*:\s*(.*)", line_stripped)
        if m:
            rt = m.group(1) or m.group(2)
            current["radio_type"] = rt.strip()
            continue
    # 收尾
    if current_bssid:
        current.setdefault("bssids", []).append(current_bssid)
    if current:
        networks.append(current)
    return networks


def channel_to_frequency(channel):
    """WiFi 信道转频率"""
    if 1 <= channel <= 13:
        return 2407 + channel * 5  # 2.4GHz
    elif channel == 14:
        return 2484
    elif 36 <= channel <= 177:
        return 5000 + channel * 5  # 5GHz
    return 0


def is_5ghz_channel(channel):
    return channel >= 36


# ============================================================
# SECTION 4: DIAGNOSTIC MODULES
# ============================================================

class DHCPDetector:
    """DHCP 多服务器干扰检测"""

    def __init__(self):
        self.name = "DHCP 服务器检测"
        self.results = {}

    def detect_scapy(self, timeout=10):
        """使用 scapy 发送 DHCP Discover 并捕获 Offer"""
        servers = []
        _ensure_scapy()
        if not SCAPY_AVAILABLE:
            return servers, "scapy 未安装 (需要 Npcap)"

        try:
            conf.verb = 0
            # 构造 DHCP Discover, 使用真实网卡 MAC
            #
            # 旧版硬编码 00:11:22:33:44:55 有两个问题:
            #   1) DHCP server 收到 Discover 时记录的是 chaddr=00:11:22:33:44:55,
            #      OFFER 报文以广播方式发出 (因为 chaddr 不是本机 MAC, 服务器认为
            #      client 不在同一链路), 依赖网卡 promiscuous mode 才能收到;
            #   2) 与本机真实 IP/MAC 关联的 DHCP 缓存会被「假 client」污染。
            # 改为用本机 iface 的真实 MAC 后, 报文路径更标准, 也能在非 promiscuous
            # 下工作 (在多数 Npcap 配置下)。
            try:
                client_mac = get_if_hwaddr(conf.iface)
                client_mac_bytes = bytes.fromhex(client_mac.replace(":", ""))
            except Exception:
                client_mac = "00:11:22:33:44:55"
                client_mac_bytes = b"\x00\x11\x22\x33\x44\x55"

            dhcp_discover = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac) /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(op=1, chaddr=client_mac_bytes) /
                DHCP(options=[("message-type", "discover"), "end"])
            )
            # 发送并接收响应
            ans, unans = srp(
                dhcp_discover, timeout=timeout, multi=True,
                iface=conf.iface, verbose=0
            )
            # 按 (server_ip, server_mac) 去重: 同一服务器可能因 retransmission
            # 响应多次, 旧实现会重复计数, 把单服务器误判为「多服务器干扰」。
            seen = set()
            for snd, rcv in ans:
                if rcv.haslayer(DHCP):
                    dhcp_opts = rcv[DHCP].options
                    server_id = None
                    lease_time = None
                    msg_type = None
                    for opt in dhcp_opts:
                        if opt[0] == "server_id":
                            server_id = opt[1]
                        elif opt[0] == "lease_time":
                            lease_time = opt[1]
                        elif opt[0] == "message-type":
                            msg_type = opt[1]
                    if msg_type == 2:  # DHCPOFFER
                        offered_ip = rcv[BOOTP].yiaddr
                        server_mac = rcv[Ether].src
                        sip = server_id or str(rcv[IP].src)
                        key = (str(sip), str(server_mac))
                        if key in seen:
                            continue
                        seen.add(key)
                        servers.append({
                            "server_ip": sip,
                            "server_mac": server_mac,
                            "offered_ip": str(offered_ip),
                            "lease_time": lease_time or 86400,
                        })
        except Exception as e:
            return servers, f"scapy 检测失败: {e}"

        return servers, None

    def detect_fallback(self):
        """无 scapy 时的降级检测: ipconfig + 事件日志"""
        servers = []
        # 当前 DHCP 服务器
        code, out, _ = run_cmd("ipconfig /all")
        for line in out.split("\n"):
            if "DHCP Server" in line or "DHCP 服务器" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ip = parts[1].strip()
                    try:
                        ipaddress.IPv4Address(ip)
                        # 查找 MAC
                        code2, arp_out, _ = run_cmd("arp -a")
                        mac = "未知"
                        for arp_line in arp_out.split("\n"):
                            if ip in arp_line:
                                mac_match = re.search(r"([0-9a-fA-F-]{17})", arp_line)
                                if mac_match:
                                    mac = mac_match.group(1)
                                    break
                        servers.append({
                            "server_ip": ip,
                            "server_mac": mac,
                            "offered_ip": get_local_ip(),
                            "lease_time": None,  # ipconfig 不提供租约时间, 0 会误读为"0秒租约"
                            "source": "ipconfig"
                        })
                    except Exception:
                        pass
        return servers

    def detect(self, callback=None):
        """执行 DHCP 检测"""
        if callback:
            callback("正在检测 DHCP 服务器...")
        servers = []
        errors = []
        method = "unknown"
        current_dhcp = None       # ipconfig 显示的当前生效 DHCP 服务器
        offer_sources = []        # scapy 实际响应 Offer 的服务器
        dhcp_conflict = False     # 当前生效者 ≠ Offer 源 (存在抢答)

        if SCAPY_AVAILABLE:
            servers, err = self.detect_scapy(timeout=10)
            if err:
                errors.append(err)
            method = "scapy"
            if servers:
                # 对比: ipconfig 显示的当前 DHCP 服务器 vs 实际 Offer 源。
                # 两者不一致 = 有第二个 DHCP 在抢答 (如误开 DHCP 的家用路由),
                # 是装维定位"IP 段/网关/DNS 异常"的高价值线索。
                for fs in self.detect_fallback():
                    if fs.get("source") == "ipconfig":
                        current_dhcp = fs["server_ip"]
                        break
                offer_sources = sorted({s["server_ip"] for s in servers})
                if current_dhcp and current_dhcp not in offer_sources:
                    dhcp_conflict = True
            else:
                servers = self.detect_fallback()
                method = "scapy+fallback"
        else:
            servers = self.detect_fallback()
            method = "ipconfig"
            errors.append("scapy 未安装，仅能检测当前 DHCP 服务器 (需要 Npcap 进行完整检测)")

        # 分析结果
        interference = len(servers) > 1
        if dhcp_conflict:
            errors.append(
                f"检测到 DHCP 抢答: 实际响应 Offer 的服务器 ({', '.join(offer_sources)}) "
                f"与系统当前使用的 {current_dhcp} 不一致 — 可能存在误开 DHCP 的设备")
        self.results = {
            "servers": servers,
            "interference": interference,
            "current_dhcp_server": current_dhcp,
            "offer_sources": offer_sources,
            "dhcp_conflict": dhcp_conflict,
            "method": method,
            "errors": errors,
            "timestamp": datetime.now().isoformat(),
            "summary": f"发现 {len(servers)} 个 DHCP 服务器" +
                       (" — 存在多服务器干扰!" if interference else "") +
                       (" — 检测到 DHCP 抢答!" if dhcp_conflict else " — 正常"),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class GatewayTester:  # @deprecated v1.2.0 (B7): 已迁移到 probe_gateway_v2 (SECTION 1e)
    """网关延迟 / 丢包检测"""

    def __init__(self):
        self.name = "网关延迟检测"
        self.results = {}

    def detect(self, count=20, callback=None):
        if callback:
            callback("正在检测网关延迟...")
        gateway = get_default_gateway()
        if not gateway:
            self.results = {"error": "无法获取默认网关"}
            return self.results

        if callback:
            callback(f"Ping 网关 {gateway} ({count} 次)...")

        # 内网网关正常回复 <10ms, 但 WiFi 网关在忙时偶发 >1.5s 响应,
        # wait_ms=1500 会把这些慢回复误判为"超时丢包" (与用户手动 ping -t
        # 默认 4000ms 结果对不上)。改为 3000ms 与系统默认接近, 避免误报。
        # 进程总超时留足 count × wait + 启动开销, 防 stdout 被截断。
        ping_result = ping_host(gateway, count=count, timeout=count + 15,
                                wait_ms=3000)

        # 评估: 分级阈值, 避免 53ms 0% 丢包被误报"延迟严重"
        # 阈值依据: 国内普通宽带/企业网到局域网网关一般 < 10ms;
        #           50ms 以内算"略高" (常见于 2.4G WiFi);
        #           100ms 以上才算"严重" (需要排查)
        avg = ping_result["avg_ms"]
        loss = ping_result["loss_pct"]
        jitter = ping_result.get("jitter_ms", 0)
        if loss > 5 and avg > 10:
            assessment = "网络质量差"
        elif loss > 5:
            assessment = "丢包严重"
        elif loss > 0:
            assessment = "存在丢包"
        elif avg > 100:
            assessment = "延迟严重"
        elif avg > 50:
            assessment = "延迟偏高"
        elif avg > 10:
            assessment = "延迟略高"
        else:
            assessment = "正常"

        # issues 与 _issues_gateway 同一数据源: determine_status 只看
        # result["issues"], 若只放在展示层推导, 徽章 (完成) 会与卡片内容
        # (警告/异常行) 对不上。
        issues = []
        if avg >= 30:
            issues.append({
                "type": "gateway_high_latency", "severity": "critical",
                "message": f"网关平均延迟 {avg}ms 超过阈值 30ms",
                "detail": "网页加载变慢、视频会议可能卡顿、在线游戏高延迟",
                "action": ("① 检查网线是否松动 ② 查看 WiFi 信号强度 (<-65dBm 为弱) "
                           "③ 登录路由器后台查看 CPU 占用率 ④ 如仍未改善请联系运营商"),
            })
        elif avg >= 10:
            issues.append({
                "type": "gateway_latency_high", "severity": "warning",
                "message": f"网关平均延迟 {avg}ms 略高 (阈值 10ms)",
                "detail": "对一般上网无明显影响, 实时游戏可能有轻微延迟",
                "action": "如果频繁出现卡顿, 可检查网线质量或考虑 5GHz WiFi",
            })
        if loss >= 5:
            issues.append({
                "type": "gateway_packet_loss", "severity": "critical",
                "message": f"网关丢包 {loss}%",
                "detail": "丢包会直接导致网页加载失败、视频卡顿",
                "action": "检查网线/WiFi 信号; 排除路由器/交换机过载",
            })
        elif loss >= 1:
            issues.append({
                "type": "gateway_packet_loss", "severity": "warning",
                "message": f"网关丢包 {loss}%",
                "detail": "丢包会直接导致网页加载失败、视频卡顿",
                "action": "检查网线/WiFi 信号; 排除路由器/交换机过载",
            })
        if jitter >= 50:
            issues.append({
                "type": "gateway_jitter", "severity": "critical",
                "message": f"网关抖动 {jitter}ms 超过阈值 20ms",
                "detail": "视频会议卡顿、VoIP 通话断续、在线游戏跳ping",
                "action": "优先排查 WiFi 信号/网线质量; 路由器 QoS 设置可能也有影响",
            })
        elif jitter >= 20:
            issues.append({
                "type": "gateway_jitter", "severity": "warning",
                "message": f"网关抖动 {jitter}ms 超过阈值 20ms",
                "detail": "视频会议卡顿、VoIP 通话断续、在线游戏跳ping",
                "action": "优先排查 WiFi 信号/网线质量; 路由器 QoS 设置可能也有影响",
            })

        self.results = {
            "gateway": gateway,
            "ping": ping_result,
            "assessment": assessment,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
        }
        # <1ms 时 ping 输出整数 0, 显示 "平均 <1ms" 而非误导性的 0ms (v1.9.3)
        _a = ping_result["avg_ms"]
        _at = "<1" if (_a < 1 and ping_result.get("rtts")) else f"{_a:g}"
        self.results["summary"] = (
            f"网关 {gateway}: 平均 {_at}ms, "
            f"丢包 {ping_result['loss_pct']}%, 抖动 {ping_result['jitter_ms']}ms")
        if callback:
            callback(self.results["summary"])
        return self.results


class LoopDetector:
    """内网环路检测"""

    def __init__(self):
        self.name = "内网环路检测"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在检测内网环路...")
        issues = []
        gateway = get_default_gateway()
        local_ip = get_local_ip()

        # 1. ARP 表分析 — 检查重复 MAC
        if callback:
            callback("分析 ARP 表...")
        code, arp_out, _ = run_cmd("arp -a")
        arp_entries = []
        mac_to_ips = defaultdict(list)
        ip_to_mac = {}
        # Windows `arp -a` 会按接口分组重复输出同一 (IP,MAC,type), 去重避免误报
        seen_entries = set()
        for line in arp_out.split("\n"):
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()
                etype = m.group(3)
                key = (ip, mac, etype)
                if key in seen_entries:
                    continue
                seen_entries.add(key)
                arp_entries.append({"ip": ip, "mac": mac, "type": etype})
                mac_to_ips[mac].append(ip)
                ip_to_mac[ip] = mac

        # 检查同一 (有效单播) MAC 对应多个 IP, 可能是代理 ARP / 网关多接口
        # 关键: 必须先排除广播 (ff-ff-ff-...) / IPv4组播 (01-00-5e-...) /
        # IPv6组播 (33-33-...) / 链路层协议保留 (01-80-c2-00-00-0x) 这些 MAC,
        # 否则 "ff-ff-ff-ff-ff-ff 对应 5 个子网广播 IP" 这种正常配置会被误报。
        for mac, ips in mac_to_ips.items():
            if not _is_valid_unicast_mac(mac):
                continue  # 跳过协议保留/广播/组播
            if len(ips) > 3:
                issues.append({
                    "type": "arp_duplicate_mac",
                    "severity": "warning",
                    "message": f"MAC {mac} 对应 {len(ips)} 个 IP: {', '.join(ips[:5])}",
                    "detail": "同一单播 MAC 对应多个 IP, 可能是网关多接口/代理 ARP, 也可能是环路/ARP 欺骗"
                })

        # 3. 检查重复 ARP 响应 (网关 MAC 是否被其他 IP 共用)
        if gateway and gateway in ip_to_mac:
            gw_mac = ip_to_mac[gateway]
            same_mac_ips = [ip for ip in mac_to_ips.get(gw_mac, []) if ip != gateway]
            if same_mac_ips:
                issues.append({
                    "type": "gateway_mac_shared",
                    "severity": "info",
                    "message": f"网关 MAC {gw_mac} 也被以下 IP 使用: {', '.join(same_mac_ips[:3])}",
                    "detail": "可能是同一设备有多个接口，也可能需要进一步排查"
                })

        # 2 & 4. TTL 分析 + 丢包模式分析 — 合并为一次 ping (避免重复探测)
        # 旧版分三次 ping (count=10 取 TTL 未用 + ping -n 1 取 TTL + count=15 丢包),
        # 浪费 3-5 秒且 wait_ms=1500 会误判丢包。现合并为一次 count=15, wait_ms=3000,
        # 从同一结果提取 TTL / 丢包 / 抖动。
        if gateway:
            if callback:
                callback("TTL 与丢包模式分析...")
            ping_result = ping_host(gateway, count=15, timeout=30, wait_ms=3000)
            ttl = ping_result.get("ttl")
            # 正常内网网关 TTL 通常为 64 (Linux) 或 128 (Windows)
            # 如果 TTL 远低于预期，可能存在环路
            if ttl is not None:
                if ttl < 30:
                    issues.append({
                        "type": "low_ttl",
                        "severity": "critical",
                        "message": f"网关 TTL 异常低: {ttl} (预期 64 或 128)",
                        "detail": "TTL 过低可能表明数据包经过了过多跳，疑似网络环路"
                    })
                elif ttl < 50:
                    issues.append({
                        "type": "low_ttl",
                        "severity": "warning",
                        "message": f"网关 TTL 偏低: {ttl}",
                        "detail": "TTL 偏低，可能存在多余的网络跳转"
                    })

            # 丢包模式分析 (环路常导致间歇性丢包)
            if 0 < ping_result["loss_pct"] < 50:
                # 间歇性丢包可能是环路的征兆
                if ping_result["jitter_ms"] > ping_result["avg_ms"]:
                    # WiFi 链路抖动天然偏高 (2.4G 干扰/信道拥塞/距离), 环路
                    # 征兆判定在有线链路上更可信; 无线链路降级措辞避免误报
                    wifi_connected = False
                    try:
                        wifi_out = get_wifi_interfaces()
                        wifi_connected = any(
                            "SSID" in ln and "BSSID" not in ln
                            for ln in wifi_out.split("\n"))
                    except Exception:
                        pass
                    detail = ("间歇性丢包 + 高抖动是网络环路的典型征兆, 建议进一步排查"
                              if not wifi_connected
                              else "当前为 WiFi 链路, 抖动高更可能来自无线干扰/拥塞"
                                   "(属常见现象); 若为有线连接建议排查环路")
                    issues.append({
                        "type": "intermittent_loss",
                        "severity": "warning",
                        "message": f"网关存在间歇性丢包 ({ping_result['loss_pct']}%) "
                                   f"且抖动较大 ({ping_result['jitter_ms']}ms)",
                        "detail": detail,
                    })

        loop_detected = any(i["severity"] == "critical" for i in issues)
        warning_count = sum(1 for i in issues if i["severity"] == "warning")

        self.results = {
            "gateway": gateway,
            "local_ip": local_ip,
            "arp_entries": arp_entries,
            "issues": issues,
            "loop_detected": loop_detected,
            "warning_count": warning_count,
            "timestamp": datetime.now().isoformat(),
            "summary": f"环路检测: {'发现疑似环路!' if loop_detected else f'{warning_count} 个警告' if warning_count else '未发现环路'}",
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class ExternalNetworkTester:
    """外网延迟 / 路径 / 丢包检测。

    关键设计: 区分"目标禁拼"和"目标不可达"。
      - ping 100% 丢包 + TCP 通 = "禁拼" (ICMP 被防火墙过滤, 实际可达)
      - ping 100% 丢包 + TCP 不通 = "不可达" (网络问题/主机宕机)
    旧版只信 ping, 把所有 100% 丢包都报"不可达", 用户体验差。
    """

    def __init__(self):
        self.name = "外网网络检测"
        self.results = {}

    def detect(self, targets=None, callback=None):
        if callback:
            callback("正在检测外网连通性...")
        if targets is None:
            targets = EXTERNAL_TARGETS

        results = []

        def _test_target(item):
            # 兼容 (host, name) 和 (host, name, port) 两种格式
            if len(item) == 3:
                tip, tname, tcp_port = item
            else:
                tip, tname = item
                tcp_port = 80  # 默认 HTTP 端口

            # 1. TCP 可达性预检 (多端口试, 任一通就算可达)
            # 单一端口探测不可靠: DNS 类目标 119.29.29.29 只开 UDP 53,
            # TCP 53 经常被禁; Web 类 80/443 多数情况开。
            # 用多端口 fallback 提高准确度。
            tcp_ok, tcp_rtt, tcp_used = _tcp_probe_multi(
                tip, ports=(tcp_port, 80, 443, 53), timeout=2.0)

            # 2. Ping 测试
            ping_result = ping_host(tip, count=10, timeout=15)
            # 判定 ping 是否"100% 丢包且无回包"
            ping_total_loss = (
                ping_result["loss_pct"] >= 100 and not ping_result["rtts"])

            # 3. 三态判定: ok / icmp_blocked / unreachable
            if not tcp_ok and ping_total_loss:
                # TCP 不通 + ping 也丢 -> 真实不可达
                reachability = "unreachable"
            elif tcp_ok and ping_total_loss:
                # TCP 通 + ping 丢 -> 目标活着, ICMP 被防火墙过滤
                reachability = "icmp_blocked"
            elif tcp_ok and not ping_total_loss:
                # 都通 -> 正常
                reachability = "ok"
            else:
                # TCP 不通 + ping 有回包 -> 矛盾状态 (端口被禁, 但 host 通)
                # 例如企业内网允许 ping 但禁外网 TCP 80
                reachability = "tcp_blocked"

            # 4. Traceroute: 不可达/禁拼时跳过 (省 40s × 目标数)
            hops = []
            if reachability in ("ok", "tcp_blocked"):
                code, tracert_out, _ = run_cmd(
                    f"tracert -d -h 15 -w 1000 {tip}", timeout=40)
                hops = parse_tracert_output(tracert_out)

            # 5. DNS 解析 (如果目标是域名) - 跟 ping/TCP 独立, 总是测
            dns_time = None
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", tip):
                try:
                    start = time.time()
                    socket.gethostbyname(tip)
                    dns_time = round((time.time() - start) * 1000, 1)
                except Exception:
                    dns_time = None

            return {
                "target": tip,
                "name": tname,
                "tcp_port": tcp_port,
                "tcp_used_port": tcp_used,
                "tcp_reachable": tcp_ok,
                "tcp_rtt_ms": tcp_rtt,
                "ping_loss_pct": ping_result["loss_pct"],
                "ping_avg_ms": ping_result["avg_ms"],
                "reachability": reachability,
                "hop_count": len(hops),
                "dns_time_ms": dns_time,
                "_hops": hops,
            }

        if callback:
            callback(f"外网检测 {len(targets)} 个目标 (并发)...")
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as ex:
            for r in ex.map(_test_target, targets):
                results.append(r)

        # 综合评估: 基于 TCP 可达性 (而不是仅 ping)
        # 老逻辑用 ping loss 平均, 一个被禁拼的目标会拖累整个评估。
        # 新逻辑: TCP 可达比例 + ping 真实延迟 (在可达目标上)
        tcp_ok_count = sum(1 for r in results if r["tcp_reachable"])
        unreachable_count = sum(1 for r in results
                               if r["reachability"] == "unreachable")
        blocked_count = sum(1 for r in results
                           if r["reachability"] == "icmp_blocked")

        # 平均延迟: 优先用 TCP RTT (更真实), TCP 不可用时用 ping 延迟
        tcp_rtts = [r["tcp_rtt_ms"] for r in results
                    if r["tcp_reachable"] and r["tcp_rtt_ms"] and r["tcp_rtt_ms"] > 0]
        ping_rtts = [r["ping_avg_ms"] for r in results
                     if r["ping_avg_ms"] > 0]
        # 延迟优先用 TCP RTT (TCP 握手时间反映真实网络延迟), ping 延迟作回退
        avg_rtt = (sum(tcp_rtts) / len(tcp_rtts) if tcp_rtts
                   else sum(ping_rtts) / len(ping_rtts) if ping_rtts else 0)

        # 平均丢包: 只统计 TCP 不可达的目标 (TCP 通但 ping 丢 = ICMP 被限速/降级, 不是真丢包)
        # 旧逻辑: 在 ok/tcp_blocked 目标上也统计 ping 丢包, 导致 DNS 服务器 ICMP 限速被误报为"外网丢包"
        # 新逻辑: TCP 可达的目标 ping 丢包不算外网丢包 (ICMP 优先级低, DNS/Web 服务器会降级 ICMP)
        real_losses = [r["ping_loss_pct"] for r in results
                       if r["reachability"] == "unreachable"]
        avg_loss = sum(real_losses) / len(real_losses) if real_losses else 0
        # ICMP 丢包率 (仅作参考, 不影响告警): 在 TCP 可达但 ping 有丢包的目标上统计
        icmp_losses = [r["ping_loss_pct"] for r in results
                       if r["reachability"] in ("ok", "tcp_blocked")
                       and r["ping_loss_pct"] > 0]

        # 路径追踪记录表 (每跳一行, 供报告渲染成多列表 + 状态着色)
        traceroute = []
        for r in results:
            for h in r.pop("_hops"):
                avg = h.get("avg_ms", 0)
                status = ("超时" if h.get("timeout")
                          else ("慢" if avg > 100 else "正常"))
                traceroute.append({
                    "target": r["name"], "hop": h["hop"],
                    "node": h["ip"], "avg_ms": avg, "status": status})

        # 评估: TCP 可达性优先 (ping 丢包在 TCP 可达时不视为故障)
        if tcp_ok_count == len(results) and avg_loss == 0 and avg_rtt < 50:
            assessment = "外网连通正常"
        elif tcp_ok_count == len(results) and avg_loss < 5:
            assessment = "外网连通性良好"
        elif tcp_ok_count == len(results):
            assessment = "外网 TCP 全部可达, 存在部分丢包"
        elif unreachable_count == 0:
            # 全部 TCP 通, 但部分被禁拼 -> 实际网络正常, ICMP 被防火墙挡
            assessment = f"外网 TCP 可达 ({tcp_ok_count}/{len(results)}), " \
                         f"{blocked_count} 个目标禁拼"
        elif unreachable_count >= len(results) / 2:
            assessment = "外网严重不可达"
        else:
            assessment = f"外网部分不可达 ({unreachable_count}/{len(results)}), " \
                         f"{tcp_ok_count} 个 TCP 可达"

        # 同步写 issues 到 self.results (与 _issues_external 口径一致),
        # determine_status 才能拿到 critical/warning, 状态徽章与卡片对得上
        # (此前 issue 仅在展示层生成, 导致徽章'完成'与卡片红色'异常'割裂)
        issues = []
        if results and tcp_ok_count == 0 and unreachable_count:
            issues.append({
                "type": "external_all_unreachable", "severity": "critical",
                "message": "全部外网目标不可达",
                "detail": "出网链路中断或被防火墙整体拦截",
                "action": ("先看网关检测与链路速率; 网关正常则查本机防火墙/代理 (跑 proxy 模块)"),
            })
        elif unreachable_count:
            issues.append({
                "type": "external_some_unreachable", "severity": "warning",
                "message": f"{unreachable_count} 个外网目标不可达",
                "detail": "部分目标不通, 可能是目标站自身问题或链路单侧劣化",
                "action": "看技术细节里的路径追踪, 确定从哪一跳开始不通; 仅个别目标不通多为对端问题",
            })
        # 丢包告警: 与 _issues_external 同一口径 (v1.9.2 审查修复) — 仅当 TCP
        # 同步劣化 (有目标建连失败) 时升 critical; TCP 全通视为 ICMP 限速降 warning
        if avg_loss >= 5 and unreachable_count:
            issues.append({
                "type": "external_high_loss", "severity": "critical",
                "message": f"外网平均丢包 {avg_loss:.1f}%",
                "detail": "明显丢包: 网页卡顿、游戏掉线、视频花屏",
                "action": "网关正常而此处丢包 → 问题更可能在运营商侧, 保留报告 (含逐跳路径) 带回报障",
            })
        elif avg_loss >= 5:
            issues.append({
                "type": "external_high_loss", "severity": "warning",
                "message": f"外网平均丢包 {avg_loss:.1f}% (TCP 建连正常)",
                "detail": "TCP 可达但 ping 丢, 多为中间设备 ICMP 限速, 不一定是真实丢包",
                "action": "以实际应用体验为准; 若确有卡顿, 结合网关模块丢包判断段位",
            })
        elif avg_loss >= 1:
            issues.append({
                "type": "external_loss", "severity": "warning",
                "message": f"外网平均丢包 {avg_loss:.1f}%",
                "detail": "轻度丢包会影响游戏/通话体验",
                "action": "结合网关模块丢包判断段位: 网关也丢=内网问题; 网关不丢=外线问题",
            })
        # TCP RTT 异常告警 (TCP 握手 >500ms 说明 SYN 队列堆积或链路严重劣化)
        high_tcp_rtts = [r for r in results
                         if r["tcp_reachable"] and r["tcp_rtt_ms"]
                         and r["tcp_rtt_ms"] > 500]
        if high_tcp_rtts:
            names = ", ".join(f"{r['name']}({r['tcp_rtt_ms']:.0f}ms)" for r in high_tcp_rtts)
            issues.append({
                "type": "external_high_tcp_rtt", "severity": "warning",
                "message": f"TCP 握手延迟异常: {names}",
                "detail": "TCP 建连超过 500ms, 可能是中间设备 SYN 限速或链路拥塞",
                "action": "看路径追踪逐跳延迟; 换目标重测确认是否单点问题",
            })
        if avg_rtt >= 150:
            issues.append({
                "type": "external_high_rtt", "severity": "warning",
                "message": f"外网平均延迟 {avg_rtt:.0f}ms",
                "detail": "延迟偏高, 游戏类应用会明显感觉慢",
                "action": "看路径追踪逐跳延迟, 从哪一跳开始升高, 问题就在那一段",
            })

        # 拼接 summary 包含禁拼提示
        summary_parts = [f"外网检测: 平均延迟 {avg_rtt:.0f}ms, 丢包 {avg_loss:.1f}%"]
        if unreachable_count > 0:
            summary_parts.append(f"{unreachable_count} 个不可达")
        if blocked_count > 0:
            summary_parts.append(f"{blocked_count} 个禁拼")
        # TCP 全可达但 ICMP 有丢包时, 附注 ICMP 丢包率 (仅参考, 不影响告警)
        if icmp_losses and tcp_ok_count == len(results):
            avg_icmp_loss = sum(icmp_losses) / len(icmp_losses)
            summary_parts.append(f"ICMP 丢包 {avg_icmp_loss:.0f}% (参考, TCP 正常)")
        summary = ", ".join(summary_parts)

        self.results = {
            "targets": results,
            "traceroute": traceroute,
            "tcp_ok": tcp_ok_count,
            "tcp_total": len(results),
            "unreachable_count": unreachable_count,
            "icmp_blocked_count": blocked_count,
            "avg_loss_pct": round(avg_loss, 1),
            "avg_rtt_ms": round(avg_rtt, 1),
            "assessment": assessment,
            "issues": issues,         # 同步 issues, 让 determine_status 与展示层口径一致
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class LinkSpeedDetector:
    """有线 / WiFi 协商速率检测"""

    def __init__(self):
        self.name = "链路速率检测"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在检测链路速率...")
        adapters = get_network_adapters()
        wifi_info = get_wifi_interfaces()

        # 解析 WiFi 接口信息 (按接口分段 — 多 WiFi 网卡时互不覆盖)
        # netsh wlan show interfaces 每个接口以 "名称/Name" 行开始新段
        wifi_interfaces = []
        cur = None
        for line in wifi_info.split("\n"):
            line_s = line.strip()
            m = re.match(r"名称\s*:\s*(.*)|Name\s*:\s*(.*)", line_s)
            if m:
                if cur:
                    wifi_interfaces.append(cur)
                cur = {"name": (m.group(1) or m.group(2) or "").strip()}
                continue
            if cur is None:
                continue
            if "SSID" in line_s and "BSSID" not in line_s:
                m2 = re.match(r"SSID\s*:\s*(.*)", line_s)
                if m2:
                    cur["connected_ssid"] = m2.group(1).strip()
            elif "接收速率" in line_s or "Receive rate" in line_s:
                m2 = re.search(r":\s*([\d.]+)\s*", line_s)
                if m2:
                    cur["rx_rate"] = float(m2.group(1))
            elif "发送速率" in line_s or "Transmit rate" in line_s:
                m2 = re.search(r":\s*([\d.]+)\s*", line_s)
                if m2:
                    cur["tx_rate"] = float(m2.group(1))
            elif "信号" in line_s or "Signal" in line_s:
                m2 = re.search(r":\s*(\d+)%", line_s)
                if m2:
                    cur["signal_pct"] = int(m2.group(1))
            elif "频道" in line_s or "Channel" in line_s:
                m2 = re.search(r":\s*(\d+)", line_s)
                if m2:
                    cur["channel"] = int(m2.group(1))
            elif "无线电类型" in line_s or "Radio type" in line_s:
                m2 = re.match(r".*:\s*(.*)", line_s)
                if m2:
                    cur["radio_type"] = m2.group(1).strip()
            elif "身份验证" in line_s or "Authentication" in line_s:
                m2 = re.match(r".*:\s*(.*)", line_s)
                if m2:
                    cur["auth"] = m2.group(1).strip()
            elif "加密" in line_s or "Cipher" in line_s:
                m2 = re.match(r".*:\s*(.*)", line_s)
                if m2:
                    cur["encryption"] = m2.group(1).strip()
        if cur:
            wifi_interfaces.append(cur)

        # 信号质量分级 + 频段判定 (每块 WiFi 接口)
        for w in wifi_interfaces:
            sig = w.get("signal_pct")
            if sig is not None:
                if sig > 80:
                    w["signal_quality"] = "良好"
                elif sig >= 50:
                    w["signal_quality"] = "中等"
                else:
                    w["signal_quality"] = "较弱"
            ch = w.get("channel")
            if ch:
                w["band"] = "5GHz" if is_5ghz_channel(ch) else "2.4GHz"

        # 主 WiFi 信息 (第一个已连接的接口), 兼容旧结构 key
        wifi_details = {}
        for w in wifi_interfaces:
            if w.get("connected_ssid"):
                wifi_details = w
                break
        else:
            if wifi_interfaces:
                wifi_details = wifi_interfaces[0]

        # 解析适配器速率
        adapter_details = []
        for adapter in adapters:
            detail = {
                "name": adapter["name"],
                "description": adapter["description"],
                "status": adapter["status"],
                "media_type": adapter.get("media_type", ""),
                "is_wifi": "802.11" in adapter.get("description", "") or \
                           "Wi-Fi" in adapter["name"] or "Wireless" in adapter["name"],
                "link_speed_raw": adapter.get("link_speed", ""),
            }
            # 解析速率
            speed_str = str(adapter.get("link_speed", ""))
            m = re.search(r"([\d.]+)\s*(Gbps|Mbps|Kbps|bps)", speed_str, re.IGNORECASE)
            if m:
                val = float(m.group(1))
                unit = m.group(2).lower()
                if "gbps" in unit:
                    detail["speed_mbps"] = val * 1000
                elif "mbps" in unit:
                    detail["speed_mbps"] = val
                elif "kbps" in unit:
                    detail["speed_mbps"] = val / 1000
                else:
                    detail["speed_mbps"] = val / 1e6
            else:
                detail["speed_mbps"] = 0

            # 评估
            if adapter["status"] == "Up" or adapter["status"] == "已启用":
                if detail["is_wifi"]:
                    if detail["speed_mbps"] >= 866:
                        detail["assessment"] = "WiFi 速率优秀 (802.11ac/ax)"
                    elif detail["speed_mbps"] >= 433:
                        detail["assessment"] = "WiFi 速率良好"
                    elif detail["speed_mbps"] >= 150:
                        detail["assessment"] = "WiFi 速率一般"
                    elif detail["speed_mbps"] >= 54:
                        detail["assessment"] = "WiFi 速率较低 (802.11g)"
                    else:
                        detail["assessment"] = "WiFi 速率过低"
                else:
                    if detail["speed_mbps"] >= 1000:
                        detail["assessment"] = "千兆以太网"
                    elif detail["speed_mbps"] >= 100:
                        detail["assessment"] = "百兆以太网"
                    elif detail["speed_mbps"] >= 10:
                        detail["assessment"] = "十兆以太网"
                    else:
                        detail["assessment"] = "链路速率异常"
            else:
                detail["assessment"] = f"适配器状态: {adapter['status']}"

            adapter_details.append(detail)

        # 网卡收发错误/丢弃计数 (Get-NetAdapterStatistics, 自开机累计):
        # 网线质量差/接口接触不良的硬证据 — 速率协商正常但错误持续增长
        total_errors = total_discarded = 0
        stats_by_name = {}
        code, stats_out, _ = run_ps(
            "Get-NetAdapterStatistics | Select-Object Name, "
            "ReceivedPacketErrors, SentPacketErrors, "
            "ReceivedDiscardedPackets, SentDiscardedPackets | ConvertTo-Json")
        if stats_out and stats_out.strip():
            try:
                sdata = json.loads(stats_out)
                if not isinstance(sdata, list):
                    sdata = [sdata]
                for item in sdata:
                    if isinstance(item, dict) and item.get("Name"):
                        stats_by_name[item["Name"]] = {
                            "rx_errors": int(item.get("ReceivedPacketErrors") or 0),
                            "tx_errors": int(item.get("SentPacketErrors") or 0),
                            "rx_discarded": int(item.get("ReceivedDiscardedPackets") or 0),
                            "tx_discarded": int(item.get("SentDiscardedPackets") or 0),
                        }
            except Exception:
                pass                       # 无该 cmdlet / 解析失败 → 静默跳过, 不影响主功能
        for d in adapter_details:
            st = stats_by_name.get(d["name"])
            if not st:
                continue
            d.update(st)
            if d["status"] in ("Up", "已启用"):
                total_errors += st["rx_errors"] + st["tx_errors"]
                total_discarded += st["rx_discarded"] + st["tx_discarded"]

        # 收集需要被 status 检测器识别的告警 (determine_status 只看 result.issues 和
        # result.assessment, 不会下钻到 adapters[].assessment, 因此极低速/异常需要
        # 显式提升到顶层 issues 才能触发"警告/异常"状态)
        issues = []
        for d in adapter_details:
            if d["status"] not in ("Up", "已启用"):
                continue
            if d.get("is_wifi") and d.get("speed_mbps", 0) < 54:
                issues.append({
                    "type": "wifi_rate_low",
                    "severity": "warning",
                    "message": f"WiFi 适配器 {d['name']} 协商速率仅 {d.get('speed_mbps', 0):.1f} Mbps",
                    "detail": "极低速 WiFi 通常由信号弱/距离远/障碍物/驱动异常导致, 建议靠近路由器或检查天线",
                })
            elif (not d.get("is_wifi")) and d.get("speed_mbps", 0) > 0 \
                    and d.get("speed_mbps", 0) < 100:
                issues.append({
                    "type": "ethernet_rate_low",
                    "severity": "warning",
                    "message": f"有线适配器 {d['name']} 协商速率仅 {d.get('speed_mbps', 0):.1f} Mbps",
                    "detail": "有线协商到非千兆可能是网线/端口/驱动降速, 建议检查网线类别 (千兆需 Cat5e+) 与端口",
                })
            if (d.get("rx_errors", 0) + d.get("tx_errors", 0)) > 0:
                issues.append({
                    "type": "nic_errors",
                    "severity": "warning",
                    "message": (f"网卡 {d['name']} 收发错误 {d['rx_errors'] + d['tx_errors']} 个"
                                f" (自开机累计)"),
                    "detail": "错误计数是网线质量差/接口接触不良/驱动异常的硬证据, "
                              "速率协商正常但错误持续增长同样影响传输",
                })

        self.results = {
            "adapters": adapter_details,
            "wifi_details": wifi_details,
            "wifi_interfaces": wifi_interfaces,
            "nic_errors": {"total_errors": total_errors,
                           "total_discarded": total_discarded},
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"检测到 {len(adapter_details)} 个网络适配器" +
                       (f", 网卡错误 {total_errors}" if total_errors else "") +
                       (f", WiFi 信号: {wifi_details.get('signal_pct', 'N/A')}"
                        f" ({wifi_details.get('signal_quality', 'N/A')})"
                        if wifi_details else ""),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class WiFiAnalyzer:  # @deprecated v1.2.0 (B11): 已迁移到 probe_wifi_v2 (SECTION 1e)
    """WiFi 干扰分析"""

    def __init__(self):
        self.name = "WiFi 干扰分析"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在扫描 WiFi 网络...")
        networks = get_wifi_networks()

        if callback:
            callback(f"发现 {len(networks)} 个 WiFi 网络，分析信道干扰...")

        # 信道分析
        channel_2g = defaultdict(list)  # channel -> [(ssid, bssid, signal)]
        channel_5g = defaultdict(list)
        all_bssids = []

        for net in networks:
            ssid = net.get("ssid", "(隐藏)")
            for bssid_info in net.get("bssids", []):
                ch = bssid_info.get("channel", 0)
                sig = bssid_info.get("signal", 0)
                entry = {
                    "ssid": ssid,
                    "bssid": bssid_info.get("bssid", ""),
                    "signal": sig,
                    "channel": ch,
                    "auth": bssid_info.get("auth", net.get("auth", "")),
                    "encryption": net.get("encryption", ""),
                    "radio_type": net.get("radio_type", ""),
                    "freq": channel_to_frequency(ch) if ch else 0,
                    "is_5g": is_5ghz_channel(ch) if ch else False,
                }
                all_bssids.append(entry)
                if ch:
                    if is_5ghz_channel(ch):
                        channel_5g[ch].append(entry)
                    else:
                        channel_2g[ch].append(entry)

        # 计算每个信道的干扰等级
        channel_analysis = []
        for ch in sorted(set(list(channel_2g.keys()) + list(channel_5g.keys()))):
            entries = channel_2g.get(ch, []) + channel_5g.get(ch, [])
            # 2.4GHz 信道重叠分析 (每个信道覆盖 +-2)
            if not is_5ghz_channel(ch):
                overlap_count = 0
                overlap_strong = 0
                for adj_ch in range(max(1, ch - 4), min(14, ch + 5)):
                    if adj_ch != ch:
                        for entry in channel_2g.get(adj_ch, []):
                            overlap_count += 1
                            if entry["signal"] > 50:
                                overlap_strong += 1
                interference_score = len(entries) * 2 + overlap_count + overlap_strong * 3
            else:
                # 5GHz 信道重叠少
                interference_score = len(entries)

            if interference_score >= 15:
                level = "严重"
            elif interference_score >= 8:
                level = "较高"
            elif interference_score >= 4:
                level = "中等"
            elif interference_score >= 1:
                level = "轻微"
            else:
                level = "无干扰"

            channel_analysis.append({
                "channel": ch,
                "band": "5GHz" if is_5ghz_channel(ch) else "2.4GHz",
                "network_count": len(entries),
                "overlap_count": overlap_count if not is_5ghz_channel(ch) else 0,
                "overlap_strong": overlap_strong if not is_5ghz_channel(ch) else 0,
                "interference_score": interference_score,
                "interference_level": level,
                "networks": entries,
            })

        # 找到最佳信道
        best_2g = None
        best_5g = None
        for ca in channel_analysis:
            if ca["band"] == "2.4GHz":
                if best_2g is None or ca["interference_score"] < best_2g["interference_score"]:
                    best_2g = ca
            else:
                if best_5g is None or ca["interference_score"] < best_5g["interference_score"]:
                    best_5g = ca

        # 当前连接信息
        wifi_interfaces = get_wifi_interfaces()
        current_channel = None
        current_ssid = None
        for line in wifi_interfaces.split("\n"):
            if "频道" in line or "Channel" in line:
                m = re.search(r":\s*(\d+)", line.strip())
                if m:
                    current_channel = int(m.group(1))
            if "SSID" in line and "BSSID" not in line:
                m = re.match(r"SSID\s*:\s*(.*)", line.strip())
                if m:
                    current_ssid = m.group(1).strip()

        overall_interference = "正常"
        max_score = max((ca["interference_score"] for ca in channel_analysis), default=0)
        if max_score >= 15:
            overall_interference = "严重干扰"
        elif max_score >= 8:
            overall_interference = "干扰较高"
        elif max_score >= 4:
            overall_interference = "存在干扰"

        # issues 与 _issues_wifi 同一数据源: determine_status 只看 result["issues"],
        # 否则"干扰高/严重"时卡片有警告行、徽章却仍是"完成"。
        issues = []
        if "严重" in overall_interference or "较高" in overall_interference:
            issues.append({
                "type": "wifi_interference",
                "severity": "critical" if "严重" in overall_interference else "warning",
                "message": f"WiFi 信道干扰{overall_interference}",
                "detail": "WiFi 速率下降、延迟增加, 设备连接不稳定",
                "action": ("① 在路由器后台将信道切换到推荐信道 "
                           "② 优先使用 5GHz 频段 (穿墙弱但干扰少) "
                           "③ 路由器放在房屋中心位置, 远离微波炉/蓝牙设备"),
            })

        # summary: 当前信道 vs 推荐信道对比 (同频段, 装维可直接给结论)
        cur_band = None
        if current_channel:
            cur_band = "5GHz" if is_5ghz_channel(current_channel) else "2.4GHz"
        channel_advice = ""
        if best_2g and cur_band == "2.4GHz" \
                and best_2g["channel"] != current_channel and best_2g["interference_score"] > 0:
            channel_advice = (f" (当前 2.4G 信道 {current_channel} 干扰较大, "
                              f"建议换到信道 {best_2g['channel']})")
        elif best_5g and cur_band == "5GHz" \
                and best_5g["channel"] != current_channel and best_5g["interference_score"] > 0:
            channel_advice = (f" (当前 5G 信道 {current_channel} 干扰较大, "
                              f"建议换到信道 {best_5g['channel']})")

        summary = f"发现 {len(all_bssids)} 个 BSSID, 干扰等级: {overall_interference}"
        if best_2g:
            summary += f", 建议 2.4G 信道 {best_2g['channel']}"
        if best_5g:
            summary += f", 建议 5G 信道 {best_5g['channel']}"
        summary += channel_advice

        self.results = {
            "networks": all_bssids,
            "network_count": len(all_bssids),
            "channel_analysis": channel_analysis,
            "best_2g_channel": best_2g,
            "best_5g_channel": best_5g,
            "current_channel": current_channel,
            "current_ssid": current_ssid,
            "overall_interference": overall_interference,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class _LiveUI:
    """测速过程的终端实时可视化 (ANSI 动画)。

    仅在"单独运行测速模块 + TTY + 非 JSON/非 verbose"时启用 (live_ui=True)。
    速率柱状图 + 实时数字 + 阶段/延迟提示, 每 0.15s 最多刷新一次。
    """

    def __init__(self, enabled):
        self.enabled = bool(enabled) and sys.stdout.isatty() and not _C_NOCOLOR
        self._last = 0.0

    def draw(self, down=None, up=None, phase="", idle_rtt=None, loaded_rtt=None):
        if not self.enabled:
            return
        now = time.time()
        if now - self._last < 0.15:
            return
        self._last = now
        d = down if down is not None else 0
        u = up if up is not None else 0
        scale = max(d, u, 1.0)
        n = int(d / scale * 18)
        bar_d = "#" * n + "-" * (18 - n)
        n = int(u / scale * 18)
        bar_u = "#" * n + "-" * (18 - n)
        rtt_str = ""
        if idle_rtt is not None:
            rtt_str = f"延迟 {idle_rtt:.0f}ms"
            if loaded_rtt is not None:
                rtt_str += f" → {loaded_rtt:.0f}ms"
        line = (f"\r\033[K  \033[96m↓ {d:8.1f} Mbps {bar_d}   "
                f"↑ {u:8.1f} Mbps {bar_u}   {phase}  {rtt_str}\033[0m")
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        if self.enabled:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


class SpeedTester:
    """内外网测速模块"""

    def __init__(self):
        self.name = "网络测速"
        self.results = {}

    def test_ookla(self, callback=None, server_id=None):
        """Ookla Speedtest CLI 官方测速 (可选, --speedtest-net 启用)。

        用 speedtest.exe (Ookla 官方 CLI) 替代旧版 speedtest-cli Python 库:
          - 输出 --format=json 结构化 JSON, 含 download/upload/ping/packetLoss/result_url
          - 支持 -s <id> 指定服务器 (解决国内选点偏海外的问题, --speedtest-node 传数字 ID)
          - 首次运行需 --accept-license --accept-gdpr (已内置, 用户无感)
          - 零 Python 依赖 (exe 随发行版打包)

        服务器国家判断保留: 选中海外服务器时标记 valid=False 并附 note。
        """
        if callback:
            callback("Ookla Speedtest 官方测速中 (可选, 结果仅供参考)...")
        exe = _find_ookla_speedtest()
        if not exe:
            return {"error": "未找到 speedtest.exe (Ookla CLI), 无法运行官方测速; "
                             "可从 speedtest.net 下载放入 speedtest/ 子目录",
                    "method": "ookla"}

        # 构造命令: --format=json 输出纯 JSON (含 log + result 两种 type)
        # --accept-license --accept-gdpr 首次运行自动接受 (项目非商用, 已确认合规)
        cmd_parts = [f'"{exe}"', "--format=json", "--accept-license", "--accept-gdpr"]
        if server_id:
            cmd_parts += ["-s", str(server_id)]
        cmd = " ".join(cmd_parts)

        if callback:
            if server_id:
                callback(f"  指定服务器 ID: {server_id}")
            else:
                callback("  自动选择最近服务器 (国内可能选到海外, 结果仅供参考)...")

        # Ookla 测速通常 30-60s (下载 + 上传各 ~15s + 选服 + ping)
        code, out, err = run_cmd(cmd, timeout=120, shell=True, use_cache=False)
        if code != 0 and not out:
            return {"error": f"speedtest.exe 执行失败 (code={code}): {err}",
                    "method": "ookla"}

        # 解析 JSON 输出: Ookla CLI 会输出多行 JSON (log + result), 取 type=="result" 的那行
        result_data = None
        for line in out.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "result":
                    result_data = obj
                    break
            except json.JSONDecodeError:
                continue
        if not result_data:
            # 优先提取 log 行的 message (可读原因), 避免把 base64 协议握手噪声塞进错误
            fail_msg = ""
            for line in out.strip().splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("type") == "log" and obj.get("message"):
                    msg = str(obj["message"]).strip()
                    # 优先 error/warning 级 (info 级如 "Speedtest is running" 是流水日志)
                    if obj.get("level") in ("error", "warning", "warn", "fatal", "critical"):
                        fail_msg = msg
                        break
                    if not fail_msg:
                        fail_msg = msg
            if fail_msg:
                err_text = f"speedtest.exe 无有效 result 行: {fail_msg[:80]}"
            else:
                err_text = "speedtest.exe 输出异常 (无有效 result 行)"
            return {"error": err_text, "method": "ookla"}

        # 提取字段 (Ookla JSON 结构):
        #   download.bandwidth: bytes/s  → Mbps (×8 / 1e6)
        #   upload.bandwidth: bytes/s
        #   ping.latency / ping.jitter: ms
        #   packetLoss: 0.0-1.0 (小数)
        #   server.id / name / location / country / cc
        #   result.url: speedtest.net 结果页链接
        #   isp: 用户运营商
        try:
            dl_bw = result_data.get("download", {}).get("bandwidth", 0) or 0
            ul_bw = result_data.get("upload", {}).get("bandwidth", 0) or 0
            ping_obj = result_data.get("ping", {}) or {}
            latency = ping_obj.get("latency", 0) or 0
            jitter = ping_obj.get("jitter", 0) or 0
            packet_loss = result_data.get("packetLoss", 0) or 0
            server_obj = result_data.get("server", {}) or {}
            result_url = (result_data.get("result", {}) or {}).get("url", "")
            isp = result_data.get("isp", "")

            download_mbps = round(dl_bw * 8 / 1e6, 2)  # bytes/s → Mbps
            upload_mbps = round(ul_bw * 8 / 1e6, 2)
            country = str(server_obj.get("country", "") or "")
            cc = str(server_obj.get("cc", "") or "").upper()
            server_name = str(server_obj.get("name", "") or "")
            server_loc = str(server_obj.get("location", "") or "")
            sponsor = str(server_obj.get("sponsor", "") or server_obj.get("name", "") or "")

            # 中国大陆 + 港澳台视为"国内可达", 其它 (海外) 标记结果无效
            # 注意: Ookla JSON 中 country 可能是英文 "China"/"Hong Kong" 或中文 "中国"
            valid = (cc in ("CN", "HK", "MO", "TW")
                     or "中国" in country or "China" in country
                     or "Hong Kong" in country
                     or "Macao" in country or "Macau" in country
                     or "Taiwan" in country)

            result = {
                "method": "ookla",
                "server": f"{sponsor} ({server_name}, {country})".strip(),
                "server_country": country,
                "server_cc": cc,
                "server_id": server_obj.get("id", ""),
                "server_latency_ms": round(latency, 1),
                "download_mbps": download_mbps,
                "upload_mbps": upload_mbps,
                "jitter_ms": round(jitter, 2),
                "packet_loss_pct": round(packet_loss * 100, 2),
                "result_url": result_url,
                "isp": isp,
                "valid": valid,
            }
            if not valid:
                result["note"] = (f"Ookla 选中服务器位于海外 ({country}), "
                                  "跨境链路测速结果不代表本地宽带速率, 仅供参考; "
                                  "可用 --speedtest-node <国内服务器ID> 指定国内节点")
            if callback:
                callback(f"  Ookla 完成: ↓{download_mbps} Mbps ↑{upload_mbps} Mbps "
                         f"({sponsor}, {country})")
            return result
        except Exception as e:
            return {"error": f"解析 Ookla 结果失败: {e}", "method": "ookla",
                    "raw_output": out[:500]}

    # 旧版兼容别名 (外部如有调用 test_speedtest 仍可用, 内部转发到 test_ookla)
    def test_speedtest(self, callback=None, **kw):
        return self.test_ookla(callback=callback, server_id=kw.get("server_id"))

    def test_http(self, callback=None, on_sample=None, series=None):
        """HTTP 多连接下载测速 (默认主测速路径)。

        旧版问题 (用户已踩):
          - 测速源 speedtest.tele2.net / cachefly.cachefly.net 是国外 CDN,
            从国内访问极慢 (17KB/s 量级), 完整下载 10MB 文件要 5-10 分钟
          - resp.read() 一次读完全部数据, 必须等服务器发完才返回
          - timeout=15s 在慢链路上必然超时, 但用户只看到 "HTTP 下载测速中...",
            不知道是卡了还是快好了
          - 单连接测速, 高速宽带 (300M+) 下打不满, 数字偏低

        当前实现:
          - 国内大文件镜像 (腾讯/华为, 实测在线, ~790MB boot.iso) 多连接并发,
            每个连接累计 target_bytes 就停, 不等下完
          - Cloudflare __down 仅作最后兜底 (从国内访问实测只有 ~1Mbps, 结果
            会标注"海外源"提示)
          - 计时从首字节开始 (排除 TCP/TLS 握手), 慢链路也能给出"低速率"结果
          - on_sample / series: 实时速率采样回调与时间序列 (终端动画 + 报告曲线)
        """
        if callback:
            callback("HTTP 下载测速中...（国内镜像多连接）")
        # 候选列表按实测速率排序: 腾讯主域 > 华为云 > Cloudflare (兜底)。
        # centos 8 已 EOL, 清华/阿里部分路径已下线 (实测 404 / 拒连), 已移除。
        test_urls = [
            "https://mirrors.tencent.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            "https://mirrors.huaweicloud.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            "https://speed.cloudflare.com/__down?bytes=10485760",
        ]
        for url in test_urls:
            if callback:
                callback(f"  测速源: {url[:60]}{'...' if len(url) > 60 else ''}")
            seg_series = []
            result = _download_speed_multi(
                url, threads=4,
                target_bytes=800 * 1024 * 1024,   # 字节上限 (防失控), 实际窗口由时长决定
                overall_timeout=20,
                max_duration=SPEEDTEST_CONFIG.get("duration_down", 8.0),
                on_sample=on_sample, series=seg_series)
            if result and result.get("downloaded_mb", 0) > 0.1:
                # 至少下到 100KB 才认为有效 (避免空响应/被劫持的短响应)
                # 合并本段采样点到总序列 (时间偏移 = 前面各段累计时长)
                if series is not None:
                    base_t = series[-1][0] if series else 0.0
                    for t, v in seg_series:
                        series.append((round(base_t + t, 2), v))
                if "cloudflare" in url:
                    result["note"] = ("测速源为海外 CDN (Cloudflare), 国内链路下"
                                      "结果偏低, 不代表真实宽带速率")
                return result
        return {"error": "所有 HTTP 测速服务器均不可用或太慢", "method": "http_download"}

    def test_upload_domestic(self, callback=None, duration=8.0, node=None,
                             on_sample=None, series=None):
        """国内运营商节点上行测速: 多连接 HTTP POST 上传 (speedtest 协议)。

        零第三方依赖: 节点来自内置的 DOMESTIC_SPEEDTEST_NODES (电信/联通/
        移动官方测速服务器), 不依赖 Ookla 动态列表 (代理环境会选到海外节点,
        且该接口常被限流)。自动选延迟最低节点, 也可用 --speedtest-node
        手动指定 host:port。

        on_sample / series: 实时速率采样回调与时间序列 (终端动画 + 报告曲线)。
        """
        if callback:
            callback("探测国内测速节点 (电信/联通/移动)...")
        try:
            if node:
                server = self._resolve_node(node)
                if not server:
                    return {"error": f"无法解析测速节点: {node} (支持数字 ID 或 "
                                     "host:port, 如 3633 或 112.25.80.50:8080)",
                            "method": "upload_cn"}
                # 数字 ID 是 Ookla 服务器, 不走国内上行节点逻辑 (由 test_ookla 处理)
                if server.get("type") == "ookla_id":
                    return {"error": "数字 ID 仅用于 Ookla 官方测速 (--speedtest-net), "
                                     "国内上行节点请用 host:port 格式",
                            "method": "upload_cn"}
            else:
                server, err = _select_domestic_speedtest_server(callback)
                if not server:
                    return {"error": err, "method": "upload_cn"}
            host = server.get("host", "")
            if not host:
                return {"error": "测速节点缺少 host 信息", "method": "upload_cn"}
            sponsor = server.get("sponsor", "") or host
            if callback:
                callback(f"上行测速: {sponsor} ({host})")
            lat = _tcping_ms(host, timeout=3)
            res = _upload_speed_multi(host, threads=4, duration=duration,
                                      on_sample=on_sample, series=series)
            if not res:
                return {"error": f"上行测速失败: {host}", "method": "upload_cn"}
            res.update({
                "method": "speedtest-cn",
                "sponsor": sponsor,
                "server_host": host,
                "server_latency_ms": lat,
            })
            return res
        except Exception as e:
            return {"error": str(e), "method": "upload_cn"}

    def _resolve_node(self, node):
        """解析 --speedtest-node: 支持两种格式。

        - 数字 ID (如 3633): Ookla Speedtest 服务器 ID, 传给 speedtest.exe -s <id>
        - host:port (如 112.25.80.50:8080): 国内运营商上行节点 (speedtest 协议)

        返回 dict: {"type": "ookla_id", "server_id": 3633} 或
                   {"type": "host_port", "host": "...", "sponsor": "...", ...}
        """
        node = str(node).strip()
        # 纯数字 → Ookla 服务器 ID
        if node.isdigit():
            return {"type": "ookla_id", "server_id": int(node)}
        # host:port → 国内上行节点
        host, _, port = node.rpartition(":")
        if not host or not port.isdigit():
            return None
        return {"type": "host_port", "host": f"{host}:{port}",
                "sponsor": node, "cc": "CN", "country": "手动指定"}

    def detect(self, use_speedtest_net=False, node=None, live_ui=False,
               ookla_server_id=None, save_report=True, callback=None):
        """完整测速 (带宽体检) — 纯互联网宽带测速, 不含 iperf3 (iperf3 已是独立模块)。

        流程: ① 空闲延迟基线 → ② 下行测速 (国内镜像多连接, 并行采样负载延迟)
        → ③ 上行测速 (国内运营商节点) → ④ 汇总评级
        (下行/上行/预估带宽/bufferbloat A-F) → ⑤ 本地 HTML+JSON 报告。

        live_ui: 单独运行本模块时终端实时动画 (由 run_diagnostics 置位)。
        save_report: 结束后保存独立测速报告到 reports/YYYY-MM-DD/。

        use_speedtest_net: 启用 Ookla 官方测速 (交互菜单默认启用, CLI 需 --speedtest-net)。
        ookla_server_id: Ookla 服务器 ID (默认 3633=上海电信, 避免 auto-select 偏海外)。
        """
        # live_ui 时抑制阶段文本 callback, 避免与终端实时动画 (\r 刷新) 互相覆盖
        def _cb(msg):
            if live_ui:
                return
            if callback:
                callback(msg)

        if callback:
            callback("开始宽带测速 (带宽体检)...")
        t_start = time.time()

        # 延迟采样目标: 网关优先 (bufferbloat 的测量对象), 无网关用公共 DNS
        lat_target = get_default_gateway() or "223.5.5.5"
        monitor = LatencyMonitor(lat_target)
        monitor_ok = monitor.start()

        # ① 空闲延迟基线 (约 3 个样本, ~3s)
        if callback:
            callback("测量空闲延迟基线...")
        if monitor_ok:
            monitor.wait_samples(3, timeout=6)
        idle_rtt = monitor.median_rtt() if monitor_ok else None

        ui = _LiveUI(live_ui)
        ui.draw(phase="准备", idle_rtt=idle_rtt)

        # ② 下行测速 (并行采样负载延迟)
        down_series = []
        up_series = []

        def _down_sample(inst, t_off, cum):
            ui.draw(down=inst, phase="下行测速", idle_rtt=idle_rtt)

        down_start = time.time()
        http_result = self.test_http(_cb, on_sample=_down_sample,
                                     series=down_series)
        down_end = time.time()
        loaded_down_rtt = monitor.median_rtt(since=down_start) if monitor_ok else None
        down_lat_series = monitor.series_since(down_start) if monitor_ok else []

        # ③ 上行测速 (国内运营商节点, 零依赖)
        upload = None
        up_result = None
        loaded_up_rtt = None
        up_lat_series = []

        def _up_sample(inst, t_off, cum):
            ui.draw(up=inst, phase="上行测速", idle_rtt=idle_rtt)

        up_start = time.time()
        up_result = self.test_upload_domestic(
            _cb, duration=SPEEDTEST_CONFIG.get("duration_up", 8.0),
            node=node, on_sample=_up_sample, series=up_series)
        if "error" not in up_result:
            upload = up_result.get("upload_mbps")
        up_end = time.time()
        if monitor_ok:
            loaded_up_rtt = monitor.median_rtt(since=up_start)
            up_lat_series = monitor.series_since(up_start)
        monitor.stop()

        # ④ 汇总评级
        download = 0.0
        method_bits = []
        if "error" not in http_result:
            download = http_result.get("download_mbps", 0)
            method_bits.append("国内HTTP")
        if up_result and "error" not in up_result:
            method_bits.append("国内节点上行")
        if not method_bits:
            method_bits.append("失败")

        # 延迟: 取下行/上行负载中较差者
        loaded_rtt = None
        loaded_phase = None
        if loaded_down_rtt is not None and loaded_up_rtt is not None:
            if loaded_up_rtt >= loaded_down_rtt:
                loaded_rtt, loaded_phase = loaded_up_rtt, "上行"
            else:
                loaded_rtt, loaded_phase = loaded_down_rtt, "下行"
        elif loaded_down_rtt is not None:
            loaded_rtt, loaded_phase = loaded_down_rtt, "下行"
        elif loaded_up_rtt is not None:
            loaded_rtt, loaded_phase = loaded_up_rtt, "上行"
        grade_text, bloat_ms = bufferbloat_grade(idle_rtt, loaded_rtt)

        est = estimate_bandwidth(download, upload)

        # 延迟时间序列 (空闲 + 下行 + 上行 全段)
        lat_series = monitor.series_since(t_start) if monitor_ok else []

        # Ookla Speedtest 官方测速 (交互菜单默认启用, CLI 需 --speedtest-net)
        # 服务器选择优先级: --speedtest-node <数字ID> > ookla_server_id (默认 3633 上海电信)
        # --speedtest-node 传 host:port 时只影响国内上行节点, 不影响 Ookla 选点
        speedtest_result = None
        if use_speedtest_net:
            final_ookla_id = ookla_server_id  # 默认 3633 (上海电信)
            if node:
                resolved = self._resolve_node(node)
                if resolved and resolved.get("type") == "ookla_id":
                    final_ookla_id = resolved.get("server_id")
            speedtest_result = self.test_ookla(_cb, server_id=final_ookla_id)

        results = {
            "download_mbps": round(download, 2),
            "upload_mbps": round(upload, 2) if upload is not None else None,
            "download_method": "国内HTTP多连接",
            "upload_method": (up_result.get("method", "未知")
                              if up_result else "未测"),
            "upload_server": (up_result.get("sponsor", "") if up_result else "未测"),
            "estimated_bandwidth": est,
            "idle_rtt_ms": (round(idle_rtt, 1) if idle_rtt is not None else None),
            "loaded_rtt_ms": (round(loaded_rtt, 1) if loaded_rtt is not None else None),
            "loaded_phase": loaded_phase,
            "bufferbloat_grade": grade_text,
            "bufferbloat_ms": (round(bloat_ms, 1) if bloat_ms is not None else None),
            "down_series": down_series,
            "up_series": up_series,
            "lat_series": lat_series,
            "http": http_result,
            "speedtest": speedtest_result,
            "up_result": up_result,
            "latency_target": lat_target,
            "timestamp": datetime.now().isoformat(),
        }

        up_str = f"↑{format_speed(upload)}" if upload is not None else "↑未测"
        est_str = f", 预估宽带 {est['text']}" if est else ""
        bb_str = f", 缓冲膨胀 {grade_text}" if idle_rtt is not None else ""
        results["summary"] = (f"测速 ({'+'.join(method_bits)}): "
                              f"↓{format_speed(download)}, {up_str}"
                              f"{est_str}{bb_str}")

        # ⑤ 报告保存 (在 summary 赋值之后, 保证 JSON 快照完整)
        if save_report:
            try:
                paths = save_speedtest_report(results)
                if paths:
                    results["report_html"] = paths[0]
                    results["report_json"] = paths[1]
                    _cb(f"测速报告已保存: {paths[0]}")
                    if live_ui and sys.stdout.isatty():
                        try:
                            webbrowser.open("file:///" + paths[0].replace("\\", "/"))
                        except Exception:
                            pass
            except Exception as e:
                _cb(f"测速报告保存失败: {e}")

        ui.finish()
        results["timestamp"] = datetime.now().isoformat()
        _cb(results["summary"])
        self.results = results    # 关键: 同步到 self.results (其它模块都用这个)
        return results


class Iperf3Tester:
    """iperf3 点对点吞吐测试 (到指定服务器的链路吞吐, 非互联网宽带)。

    与 SpeedTester(宽带测速) 完全解耦: 本模块只回答"到某台 iperf3 服务器的
    上下行吞吐是多少", 不掺任何互联网宽带数字, 也不参与"预估宽带/Buffferbloat"
    之类的宽带体检评级。iperf3 服务器通常部署在出口/IDC/内网, 测的是这一段链路的
    真实带宽, 数值高低取决于服务器位置 (内网会很高、公网才接近宽带)。
    """

    def __init__(self):
        self.name = "iperf3 吞吐"
        self.results = {}

    # ── iperf3.exe 定位 (优先当前目录 → 程序目录 → PATH → 交互式下载) ──
    def _find_iperf3(self, auto_download=True):
        """查找 iperf3.exe (auto_download=True 时找不到则交互式询问下载)"""
        exe_name = "iperf3.exe"
        if os.path.exists(exe_name):
            return os.path.abspath(exe_name)
        app_dir = os.path.dirname(os.path.abspath(
            sys.argv[0] if getattr(sys, 'frozen', False) else __file__))
        path = os.path.join(app_dir, exe_name)
        if os.path.exists(path):
            return path
        # 程序目录不可写时 _download_iperf3 的回退落点: %LOCALAPPDATA%\NetPulse\
        # (补上这层查找, 避免"上次自动下载成功, 这次又提示未找到"反复询问)
        fallback = os.path.join(
            os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
            "NetPulse", exe_name)
        if os.path.exists(fallback):
            return fallback
        code, out, _ = run_cmd("where iperf3", timeout=5)
        if code == 0 and out.strip():
            return out.strip().split("\n")[0].strip()

        if not auto_download:
            return None
        try:
            ans = input(_c("  未找到 iperf3.exe, 是否自动下载到程序目录? [Y/n] ",
                           C_GREEN)).strip().lower()
        except (EOFError, RuntimeError):
            return None
        if ans and ans not in ("y", "yes", ""):
            return None
        print(_c("  正在下载 iperf3 (~2MB)...", C_GRAY))
        ok, result = _download_iperf3()
        if ok:
            print(_c(f"  ✓ iperf3 已就绪: {result}", C_GREEN))
            return result
        print(_c(f"  ✗ 自动下载失败: {result}", C_RED))
        print(_c("    可手动下载: https://iperf.fr/iperf-download.php "
                 "(解压后将 iperf3.exe 放到本程序同目录)", C_GRAY))
        return None

    # ── 解析单方向 iperf3 JSON 输出 ──
    def _parse_iperf3_json(self, output, direction, udp=False):
        """解析 iperf3 JSON 输出 (direction: 'download' 取 sum_received / 'upload' 取 sum_sent)。

        修复旧版 bug: 旧 SpeedTester.test_iperf3 内部算出了 intervals_mbps 但返回值里
        没带上, 导致报告上行曲线为空。这里直接按方向返回 bitrate/retransmits/时序。
        UDP 模式 (--iperf3-udp): end.sum 直接含 jitter_ms/lost_percent (TCP 无这两项);
        1 Mbps 固定发包率下速率无意义, 重点是抖动/丢包质量指标。
        """
        if not output or not output.strip():
            return {"error": "iperf3 无输出 (服务器不可达? 防火墙拦截?)"}
        try:
            data = json.loads(output)
            end = data.get("end", {})
            if udp:
                rate_block = end.get("sum", {}) or {}
            elif direction == "download":
                rate_block = end.get("sum_received", end.get("sum", {}))
            else:
                rate_block = end.get("sum_sent", end.get("sum", {}))
            bits = (rate_block or {}).get("bits_per_second", 0)
            result = {"bitrate_mbps": round(bits / 1e6, 2)}
            if udp:
                result["jitter_ms"] = round(rate_block.get("jitter_ms") or 0, 2)
                result["loss_pct"] = round(rate_block.get("lost_percent") or 0, 2)
            else:
                # 重传永远看 sum_sent (发送方才有重传); 下载方向客户端几乎不重传 → 近 0 属正常
                sent = end.get("sum_sent", {})
                result["retransmits"] = (sent or {}).get("retransmits", 0)
            intervals = data.get("intervals") or []
            series = []
            for iv in intervals:
                s = iv.get("sum", {})
                series.append(round((s.get("bits_per_second", 0)) / 1e6, 2))
            if series:
                result["intervals_mbps"] = series
            if not result.get("bitrate_mbps"):
                return {"error": "iperf3 输出无速率数据 (跑一半超时?)"}
            return result
        except Exception:
            m = re.search(r"([\d.]+)\s*(Mbits/sec|Gbits/sec|Kbits/sec)", output)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                if "Gbits" in unit:
                    val *= 1000
                elif "Kbits" in unit:
                    val /= 1000
                return {"bitrate_mbps": round(val, 2)}
            return {"error": "iperf3 输出无法解析"}

    def _run_one_direction(self, iperf3_path, server, port, duration, reverse,
                           callback, udp=False):
        label = "下载" if reverse else "上传"
        mode = "UDP 抖动/丢包" if udp else "吞吐"
        if callback:
            callback(f"iperf3 {label}测速 ({mode}, 到 {server}:{port}, {duration}s)...")
        cmd = f'"{iperf3_path}" -c {server} -p {port} -t {duration}'
        if reverse:
            cmd += " -R"
        if udp:
            # 1 Mbps 固定发包率: 测质量 (抖动/丢包) 不测吞吐, 不打满链路
            cmd += " -u -b 1M"
        cmd += " -J"
        _, out, err = run_cmd(cmd, timeout=duration + 15)
        parsed = self._parse_iperf3_json(out, "download" if reverse else "upload",
                                         udp=udp)
        if "error" in parsed and err and err.strip():
            parsed["stderr"] = err.strip().split("\n")[-1][:200]
        return parsed

    def detect(self, server=None, port=5201, duration=10,
               callback=None, save_report=True, udp=False):
        """iperf3 点对点吞吐测试主流程。

        server: iperf3 服务器地址 (必填, 由 CLI --iperf3-server 或菜单输入提供)。
        port/duration: 服务器端口 / 单方向时长。
        返回结构顶层字段即最终结论, 单方向失败不影响另一方向, 双失败才报顶层 error。
        """
        if not server:
            res = {
                "error": "未指定 iperf3 服务器。请在菜单中选择 iperf3 时输入服务器地址, "
                         "或用 CLI: netpulse.py iperf3 --iperf3-server HOST[:PORT]",
                "method": "iperf3",
            }
            self.results = res
            return res
        iperf3_path = self._find_iperf3()
        if not iperf3_path:
            res = {"error": "iperf3.exe 未找到 (请放入 PATH 或程序目录, "
                            "或在菜单中选择 iperf3 时按 Y 自动下载)",
                   "method": "iperf3"}
            self.results = res
            return res

        down = self._run_one_direction(iperf3_path, server, port, duration, True,
                                       callback, udp=udp)
        up = self._run_one_direction(iperf3_path, server, port, duration, False,
                                     callback, udp=udp)

        # 双方向都失败 → 整体失败 (否则会把 0/0 当成功结果)
        if "error" in down and "error" in up:
            results = {
                "method": "iperf3",
                "server": server, "port": port, "duration_s": duration,
                "download_mbps": None, "upload_mbps": None,
                "download_error": down.get("error"),
                "upload_error": up.get("error"),
                "error": (f"iperf3 双向均失败 — 下载: {down.get('error')}; "
                          f"上传: {up.get('error')}"),
                "note": "iperf3 测的是到服务器的链路吞吐, 非互联网宽带; 双向失败通常是"
                        "服务器未启动 / 地址端口错 / 防火墙拦截 TCP 5201。",
                "timestamp": datetime.now().isoformat(),
            }
            self.results = results
            return results

        dl = down.get("bitrate_mbps") if "error" not in down else None
        ul = up.get("bitrate_mbps") if "error" not in up else None
        if udp:
            summary = (f"iperf3 UDP 质量 (到 {server}:{port}): "
                       + " / ".join(filter(None, [
                           f"↓抖动 {down['jitter_ms']}ms 丢包 {down['loss_pct']}%"
                           if "error" not in down else None,
                           f"↑抖动 {up['jitter_ms']}ms 丢包 {up['loss_pct']}%"
                           if "error" not in up else None]) or ["双向失败"]))
        else:
            summary = (f"iperf3 链路吞吐 (到 {server}:{port}): "
                       f"↓{format_speed(dl) if dl is not None else '失败'}, "
                       f"↑{format_speed(ul) if ul is not None else '失败'}")
        results = {
            "method": "iperf3",
            "server": server,
            "port": port,
            "duration_s": duration,
            "udp": bool(udp),
            "download_mbps": dl,
            "upload_mbps": ul,
            "download_jitter_ms": down.get("jitter_ms") if "error" not in down else None,
            "download_loss_pct": down.get("loss_pct") if "error" not in down else None,
            "upload_jitter_ms": up.get("jitter_ms") if "error" not in up else None,
            "upload_loss_pct": up.get("loss_pct") if "error" not in up else None,
            "download_retransmits": down.get("retransmits", 0) if "error" not in down else None,
            "upload_retransmits": up.get("retransmits", 0) if "error" not in up else None,
            "download_intervals_mbps": down.get("intervals_mbps"),
            "upload_intervals_mbps": up.get("intervals_mbps"),
            "download_error": down.get("error") if "error" in down else None,
            "upload_error": up.get("error") if "error" in up else None,
            "note": "iperf3 测量的是到服务器 %s 的链路吞吐, 不代表互联网宽带速率"
                    % server,
            "summary": summary,
            "timestamp": datetime.now().isoformat(),
        }

        if save_report:
            try:
                paths = save_iperf3_report(results)
                if paths:
                    results["report_html"] = paths[0]
                    results["report_json"] = paths[1]
                    if callback:
                        callback(f"iperf3 报告已保存: {paths[0]}")
            except Exception as e:
                if callback:
                    callback(f"iperf3 报告保存失败: {e}")
        if callback:
            callback(summary)
        self.results = results
        return results


# ============================================================
# 独立测速报告 (HTML + JSON) — "带宽体检单"
# ============================================================

def _render_speedtest_html(res):
    """渲染独立测速报告 HTML (内联 JS canvas 画曲线, 完全离线可用)。

    面向装维人员留档/给客户看: 三大指标仪表盘 + 速率曲线 + 延迟曲线
    (bufferbloat) + 预估带宽 + 测试参数, 不含"达标判定"的结论, 只给客观数据。
    """
    # 通用页眉: 与主报告/盯障/iperf3 报告统一品牌风格 (品牌徽标 + 版本 + 时间)
    # 顶部三大指标优先用 Ookla 官方测速结果 (更具权威性), 回退到 HTTP/国内上行
    ookla = res.get("speedtest") or {}
    use_ookla = (isinstance(ookla, dict) and "error" not in ookla
                 and ookla.get("download_mbps"))

    if use_ookla:
        download = ookla.get("download_mbps", 0)
        upload = ookla.get("upload_mbps")
        idle_rtt = ookla.get("server_latency_ms")
        primary_label = "Ookla 官方测速"
        down_note = f"Ookla · {ookla.get('server', '—')}"
        up_big = f"{upload:.1f}" if upload is not None else "未测"
        ping_big = f"{idle_rtt:.0f}" if idle_rtt is not None else "—"
        up_threads = 0  # Ookla 内部管理连接数, 不显示
        upload_server = ookla.get("server", "—")
        upload_method = "Ookla 官方"
        server_lat_str = f"{idle_rtt:.0f} ms (Ookla 服务器)" if idle_rtt is not None else "—"
    else:
        download = res.get("download_mbps") or 0
        upload = res.get("upload_mbps")
        idle_rtt = res.get("idle_rtt_ms")
        primary_label = "国内测速"
        # 测速源信息: 下行 (国内镜像多连接) / 上行 (国内运营商节点)
        src_url = (res.get("http") or {}).get("url", "")
        src_domain = src_url.split("/")[2] if src_url.startswith("http") else "国内镜像"
        down_threads = (res.get("http") or {}).get("threads", 4)
        up_threads = (res.get("up_result") or {}).get("threads", 4)
        down_note = f"{down_threads} 连接 × {src_domain}"
        up_big = f"{upload:.1f}" if upload is not None else "未测"
        ping_big = f"{idle_rtt:.0f}" if idle_rtt is not None else "—"
        upload_server = res.get("upload_server") or "未测"
        upload_method = res.get("upload_method") or "未测"
        up_res = res.get("up_result") or {}
        server_lat = up_res.get("server_latency_ms")
        server_lat_str = (f"{server_lat:.0f} ms (TCP 握手)" if server_lat is not None else "—")

    est = res.get("estimated_bandwidth") or {}
    grade = str(res.get("bufferbloat_grade") or "—")
    # 把 "A (优秀, 无缓冲膨胀)" 拆成简短字母 + 评语 (与主报告 metric 卡策略一致,
    # 避免卡片被长字符串撑大)
    g0 = grade.split(" ", 1)[0] if grade and grade != "—" else "—"
    g_rest = grade[len(g0):].strip(" ()") if g0 != "—" else ""
    grade_letter = g0
    grade_note = g_rest or ""
    # idle_rtt 已在上方 Ookla/回退分支中赋值 (Ookla 用 server_latency_ms, 回退用网关延迟)
    loaded_rtt = res.get("loaded_rtt_ms")
    bloat_ms = res.get("bufferbloat_ms")
    down_series = res.get("down_series") or []
    up_series = res.get("up_series") or []
    lat_series = res.get("lat_series") or []
    ts_raw = res.get("timestamp", "")
    try:
        ts_disp = datetime.fromisoformat(ts_raw).strftime("%Y-%m-%d %H:%M:%S") if ts_raw else "—"
    except Exception:
        ts_disp = ts_raw or "—"
    local_ip = get_local_ip() or "未知"
    gateway = get_default_gateway() or "未知"
    up_mbps = upload if upload is not None else "未测"
    est_text = est.get("text", "—") if est else "—"
    est_note = est.get("note", "") if est else ""
    # upload_server / upload_method / server_lat_str 已在上方分支赋值
    idle_str = f"{idle_rtt:.0f} ms" if idle_rtt is not None else "—"
    loaded_str = f"{loaded_rtt:.0f} ms" if loaded_rtt is not None else "—"
    bloat_str = f"{bloat_ms:+.0f} ms" if bloat_ms is not None else "—"
    # down_note / up_threads / up_big / ping_big 已在上方分支赋值

    # Ookla Speedtest 官方测速结果 (可选, --speedtest-net 启用)
    # 注意: ookla 变量已在上方赋值 (用于判断 use_ookla), 这里复用
    ookla_html = ""
    if ookla and "error" not in ookla:
        ookla_dl = ookla.get("download_mbps", 0)
        ookla_ul = ookla.get("upload_mbps", 0)
        ookla_lat = ookla.get("server_latency_ms", 0)
        ookla_jit = ookla.get("jitter_ms", 0)
        ookla_loss = ookla.get("packet_loss_pct", 0)
        ookla_server = ookla.get("server", "—")
        ookla_url = ookla.get("result_url", "")
        ookla_isp = ookla.get("isp", "")
        ookla_valid = ookla.get("valid", True)
        ookla_note = ookla.get("note", "")
        # 结果页链接 (有 URL 时可点击)
        url_html = (f'<a href="{_esc_html(ookla_url)}" target="_blank">{_esc_html(ookla_url)}</a>'
                    if ookla_url else "—")
        # 海外服务器警告
        warn_html = (f'<tr><td colspan="2" style="color:#e67e22;font-size:12px;">'
                     f'⚠ {_esc_html(ookla_note)}</td></tr>' if not ookla_valid and ookla_note else "")
        ookla_html = f"""
  <div class="panel">
    <h3>Ookla Speedtest 官方测速 <span class="tag-tp">对照参考</span></h3>
    <table>
      <tr><td>服务器</td><td>{_esc_html(str(ookla_server))}</td></tr>
      <tr><td>运营商 (ISP)</td><td>{_esc_html(str(ookla_isp)) or "—"}</td></tr>
      <tr><td>下载速率</td><td>{ookla_dl:.1f} Mbps</td></tr>
      <tr><td>上传速率</td><td>{ookla_ul:.1f} Mbps</td></tr>
      <tr><td>服务器延迟</td><td>{ookla_lat:.0f} ms</td></tr>
      <tr><td>抖动 (Jitter)</td><td>{ookla_jit:.2f} ms</td></tr>
      <tr><td>丢包率</td><td>{ookla_loss:.2f}%</td></tr>
      <tr><td>结果页链接</td><td>{url_html}</td></tr>
      {warn_html}
    </table>
  </div>
"""
    elif ookla and "error" in ookla:
        ookla_html = f"""
  <div class="panel">
    <h3>Ookla Speedtest 官方测速 <span class="tag-tp">对照参考</span></h3>
    <table>
      <tr><td>状态</td><td style="color:#e74c3c;">失败: {_esc_html(str(ookla.get("error", "")))}</td></tr>
    </table>
  </div>
"""

    # 速率曲线: 下行段 (蓝) + 上行段 (橙, 时间轴偏移到下行之后)
    down_data = [[round(t, 2), v] for t, v in down_series]
    base_t = down_series[-1][0] if down_series else 0.0
    up_data = [[round(t + base_t + 1, 2), v] for t, v in up_series]

    data_js = json.dumps({
        "down": down_data,
        "up": up_data,
        "lat": lat_series,
    }, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetPulse 宽带测速报告</title>
<style>
  {_BRAND_HEADER_CSS}
  {_DIAGNOSIS_CSS}
  body {{ font-family: "Microsoft YaHei", "Segoe UI", sans-serif; margin: 0; background: #eef2f6; color: #1c2430; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 28px 20px 48px; }}
  h1 {{ font-size: 23px; margin: 0; font-weight: 600; letter-spacing: .3px; }}
  h1 .dot {{ color: #0a84ff; margin-right: 6px; }}
  .sub {{ color: #7b8794; font-size: 12.5px; margin: 6px 0 22px; }}
  .metric-row {{ display: flex; gap: 12px; margin-bottom: 12px; }}
  .metric {{ flex: 1; background: #fff; border-radius: 14px; padding: 18px 20px 14px;
             box-shadow: 0 1px 3px rgba(16,42,67,.08); border-top: 3px solid #d3dae2; }}
  .metric .label {{ color: #7b8794; font-size: 12px; margin-bottom: 4px; }}
  .metric .big {{ font-size: 40px; font-weight: 600; line-height: 1.12; letter-spacing: -1px; }}
  .metric .big .unit {{ font-size: 14px; color: #7b8794; font-weight: 400; letter-spacing: 0; }}
  .metric .note {{ color: #98a2af; font-size: 11.5px; margin-top: 4px; }}
  .metric.down {{ border-top-color: #0a84ff; }} .metric.down .big {{ color: #0a84ff; }}
  .metric.up {{ border-top-color: #ff9500; }} .metric.up .big {{ color: #ff9500; }}
  .metric.ping {{ border-top-color: #34c759; }} .metric.ping .big {{ color: #34c759; }}
  .info-row {{ display: flex; gap: 12px; margin-bottom: 18px; }}
  .info {{ flex: 1; background: #fff; border-radius: 14px; padding: 14px 18px;
           box-shadow: 0 1px 3px rgba(16,42,67,.08); }}
  .info .label {{ color: #7b8794; font-size: 12px; margin-bottom: 3px; }}
  .info .value {{ font-size: 17px; font-weight: 500; }}
  .info .note {{ color: #98a2af; font-size: 11.5px; margin-top: 2px; }}
  .panel {{ background: #fff; border-radius: 14px; padding: 18px 20px; margin-bottom: 18px;
            box-shadow: 0 1px 3px rgba(16,42,67,.08); }}
  .panel h3 {{ margin: 0 0 14px; font-size: 15px; color: #1c2430; font-weight: 500;
               display:flex;align-items:center;gap:8px; }}
  .tag-tp {{ display:inline-block; padding:2px 9px; border-radius:5px;
    font-size:11px; font-weight:600; background:#e0e7ff; color:#4338ca; letter-spacing:.2px; }}
  canvas {{ width: 100%; height: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #f0f2f5; }}
  td:first-child {{ color: #7b8794; width: 160px; }}
  .legend {{ font-size: 12px; color: #7b8794; margin-top: 10px; }}
  .legend .sw {{ display: inline-block; width: 16px; height: 4px; border-radius: 2px;
                 margin: 0 6px 2px 14px; vertical-align: middle; }}
  .legend .sw:first-of-type {{ margin-left: 0; }}
  .footer {{ color: #a4aeb8; font-size: 12px; text-align: center; margin-top: 28px; }}
</style>
</head>
<body>
<div class="wrap">
  {_render_brand_header("宽带测速报告",
                        f"测试时间: {ts_disp} &nbsp;·&nbsp; 本机 IP: {local_ip} &nbsp;·&nbsp; 网关: {gateway}")}
  <div class="sub">客观速率/延迟实测数据, 不含达标判定 · 数据来源: {primary_label}</div>

  <div class="metric-row">
    <div class="metric down">
      <div class="label">下载</div>
      <div class="big">{download:.1f}<span class="unit"> Mbps</span></div>
      <div class="note">{down_note}</div>
    </div>
    <div class="metric up">
      <div class="label">上传</div>
      <div class="big">{up_big}<span class="unit"> Mbps</span></div>
      <div class="note">{upload_server}{' · ' + str(up_threads) + ' 连接' if up_threads else ''}</div>
    </div>
    <div class="metric ping">
      <div class="label">延迟{' (Ookla服务器)' if use_ookla else ' (网关)'}</div>
      <div class="big">{ping_big}<span class="unit"> ms</span></div>
      <div class="note">{'Ookla 服务器延迟' if use_ookla else '空闲基线 · 负载下还会测一次算缓冲膨胀'}</div>
    </div>
  </div>

  <div class="info-row">
    <div class="info">
      <div class="label">预估宽带</div>
      <div class="value">{est_text}</div>
      <div class="note">按运营商档位估算{(' · ' + est_note) if est_note else ''}</div>
    </div>
    <div class="info">
      <div class="label">缓冲膨胀 Bufferbloat</div>
      <div class="value">{grade_letter}</div>
      <div class="note">空闲 {idle_str} → 负载 {loaded_str} ({bloat_str}) · {grade_note}</div>
    </div>
  </div>

  <div class="panel">
    <h3>速率曲线 <span class="tag-mbps">Mbps · 每秒采样</span></h3>
    <canvas id="speedChart" width="840" height="280"></canvas>
    <div class="legend">
      <span class="sw" style="background:#0a84ff"></span>下行 · {down_note}
      <span class="sw" style="background:#ff9500"></span>上行 · {up_threads} 连接 × 国内运营商节点
    </div>
  </div>

  <div class="panel">
    <h3>延迟变化 <span class="tag-ms">ms · 负载期间延迟上升越多, 缓冲膨胀越严重</span></h3>
    <canvas id="latChart" width="840" height="200"></canvas>
  </div>

  <div class="panel">
    <h3>测试详情</h3>
    <table>
      <tr><td>主测速方式</td><td>{'Ookla Speedtest 官方 CLI (speedtest.exe)' if use_ookla else '国内 HTTP 多连接 + 国内运营商上行'}</td></tr>
      <tr><td>下行测速</td><td>{f'Ookla 官方测速 ({ookla.get("server", "—")})' if use_ookla else f'国内镜像多连接 HTTP 下载 ({down_threads} 连接 × {src_domain})'}</td></tr>
      <tr><td>上行测速</td><td>{f'Ookla 官方测速 ({ookla.get("server", "—")})' if use_ookla else f'{upload_method} ({upload_server}) · {up_threads} 连接'}</td></tr>
      <tr><td>延迟来源</td><td>{f'Ookla 服务器延迟 {server_lat_str}' if use_ookla else f'网关 {res.get("latency_target", "—")} (空闲/负载延迟均对它测)'}</td></tr>
      <tr><td>测速节点延迟</td><td>{server_lat_str}</td></tr>
      {'<tr><td>抖动</td><td>' + f'{ookla.get("jitter_ms", 0):.2f} ms' + '</td></tr>' if use_ookla else ''}
      {'<tr><td>丢包率</td><td>' + f'{ookla.get("packet_loss_pct", 0):.2f}%' + '</td></tr>' if use_ookla else ''}
      {'<tr><td>结果链接</td><td><a href="' + _esc_html(str(ookla.get("result_url", ""))) + '" target="_blank">' + _esc_html(str(ookla.get("result_url", "—"))) + '</a></td></tr>' if use_ookla and ookla.get("result_url") else ''}
    </table>
  </div>
  {ookla_html if not use_ookla else ''}  <!-- Ookla 已作为主测速显示, 不再重复 panel -->

  <div class="footer">由 NetPulse 生成 · 报告仅为客观测速数据, 不包含达标判定</div>
</div>

<script>
var DATA = {data_js};
function multiLineChart(id, datasets) {{
  var canvas = document.getElementById(id);
  var ctx = canvas.getContext("2d");
  var W = canvas.width, H = canvas.height;
  var pad = {{l: 56, r: 16, t: 16, b: 30}};
  var iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
  ctx.clearRect(0, 0, W, H);
  var all = [];
  datasets.forEach(function(ds) {{ all = all.concat(ds.data); }});
  if (all.length < 2) {{
    ctx.fillStyle = "#999"; ctx.font = "13px sans-serif";
    ctx.fillText("无有效数据", pad.l, pad.t + 20);
    return;
  }}
  var xmin = all[0][0], xmax = all[all.length - 1][0];
  if (xmax === xmin) xmax = xmin + 1;
  var ymax = 0;
  all.forEach(function(p) {{ if (p[1] > ymax) ymax = p[1]; }});
  if (ymax <= 0) ymax = 1;
  ymax = Math.ceil(ymax * 1.15);
  ctx.strokeStyle = "#e8ecf1"; ctx.lineWidth = 1;
  for (var i = 0; i <= 4; i++) {{
    var gy = pad.t + (1 - i / 4) * ih;
    ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke();
    ctx.fillStyle = "#98a2af"; ctx.font = "11px sans-serif"; ctx.textAlign = "right";
    ctx.fillText(Math.round(ymax * i / 4), pad.l - 6, gy + 4);
  }}
  ctx.strokeStyle = "#d3dae2";
  ctx.beginPath(); ctx.moveTo(pad.l, pad.t); ctx.lineTo(pad.l, H - pad.b);
  ctx.lineTo(W - pad.r, H - pad.b); ctx.stroke();
  datasets.forEach(function(ds) {{
    if (ds.data.length < 2) return;
    var pts = ds.data.map(function(p) {{
      return [pad.l + (p[0] - xmin) / (xmax - xmin) * iw,
              pad.t + (1 - p[1] / ymax) * ih];
    }});
    if (ds.fill) {{
      var grad = ctx.createLinearGradient(0, pad.t, 0, H - pad.b);
      grad.addColorStop(0, ds.fillTop || "rgba(10,132,255,0.18)");
      grad.addColorStop(1, ds.fillBottom || "rgba(10,132,255,0.02)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(pts[0][0], H - pad.b);
      pts.forEach(function(p) {{ ctx.lineTo(p[0], p[1]); }});
      ctx.lineTo(pts[pts.length - 1][0], H - pad.b);
      ctx.closePath();
      ctx.fill();
    }}
    ctx.strokeStyle = ds.color; ctx.lineWidth = 2; ctx.lineJoin = "round";
    ctx.beginPath();
    pts.forEach(function(p, i) {{ if (i === 0) ctx.moveTo(p[0], p[1]); else ctx.lineTo(p[0], p[1]); }});
    ctx.stroke();
  }});
  ctx.fillStyle = "#98a2af"; ctx.font = "11px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("0s", pad.l, H - 8);
  ctx.fillText(Math.round(xmax) + "s", W - pad.r, H - 8);
}}
multiLineChart("speedChart", [
  {{data: DATA.down, color: "#0a84ff", fill: true, fillTop: "rgba(10,132,255,0.16)", fillBottom: "rgba(10,132,255,0.01)"}},
  {{data: DATA.up, color: "#ff9500", fill: true, fillTop: "rgba(255,149,0,0.16)", fillBottom: "rgba(255,149,0,0.01)"}}
]);
multiLineChart("latChart", [{{data: DATA.lat, color: "#34c759", fill: true, fillTop: "rgba(52,199,89,0.14)", fillBottom: "rgba(52,199,89,0.01)"}}]);
</script>
</body>
</html>"""


def _render_brand_header(title, sub_text, gradient=("#0b1f3a", "#153e6b", "#1d4e89")):
    """通用页眉 — 测速/盯障/iperf3 三种独立报告统一品牌风格,
    与主报告 (render_report_html_customer) 视觉一致。

    返回页眉 HTML 字符串。样式类名带 brand- 前缀, 由 _BRAND_HEADER_CSS
    提供 (调用方渲染器在自己的 <head> 里输出, 避免在 body 中插 <style>)。
    """
    return f"""<header class="brand-banner">
  <span class="logo"></span>
  <div class="brand-text">
    <div class="brand-row"><span class="brand-name">{_esc_html(APP_NAME)}</span><span class="brand-ver">v{_esc_html(APP_VERSION)}</span></div>
    <h1>{title}</h1>
    <div class="brand-sub">{sub_text}</div>
  </div>
</header>"""


# 页眉样式: 放 <head>, 三种报告各注入一次即可
_BRAND_HEADER_CSS = """
.brand-banner{background:linear-gradient(135deg,#0b1f3a 0%,#153e6b 55%,#1d4e89 100%);
  color:#fff;padding:24px 28px;display:flex;align-items:center;gap:16px;
  border-radius:14px;box-shadow:0 8px 24px -10px rgba(11,31,58,.45);margin-bottom:24px;
  position:relative;overflow:hidden}
.brand-banner::before{content:'';position:absolute;top:-40%;right:-15%;width:340px;height:340px;
  background:radial-gradient(circle,rgba(96,165,250,.18) 0%,transparent 70%);pointer-events:none}
.brand-banner .logo{width:36px;height:36px;border-radius:9px;
  background:linear-gradient(135deg,#7ab3f5,#3b82f6);position:relative;flex:none}
.brand-banner .logo::after{content:'';position:absolute;inset:8px;
  border:2px solid rgba(255,255,255,.92);border-radius:3px}
.brand-text{flex:1;min-width:0}
.brand-row{display:flex;align-items:center;gap:8px;margin-bottom:2px}
.brand-name{font-size:14px;font-weight:700;color:#dbeafe;letter-spacing:.3px}
.brand-ver{font-size:11px;font-weight:600;color:#bfdbfe;
  background:rgba(255,255,255,.14);padding:1px 9px;border-radius:999px}
.brand-banner h1{font-size:22px;font-weight:800;letter-spacing:.5px;margin:4px 0 2px;color:#fff}
.brand-sub{font-size:12.5px;color:#9db8dd}
"""


def save_speedtest_report(res):
    """保存独立测速报告 (HTML + JSON), 返回 (html_path, json_path)。

    落点与诊断报告统一走 _report_dir() (EXE 模式下为 EXE 所在目录,
    源码模式下为 netpulse.py 所在目录), 避免此前用相对路径 "reports"
    导致报告落点随当前工作目录 (cwd) 漂移的问题。

    报告是装维留档/给客户看的: HTML 为"带宽体检单" (含曲线), JSON 为原始
    时间序列 (供技术归档/脚本分析)。
    """
    try:
        day_dir = _report_dir()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(day_dir, f"speedtest_{stamp}.json")
        html_path = os.path.join(day_dir, f"speedtest_{stamp}.html")
        # JSON 快照: 附加自身路径 (HTML 渲染用原始 res, 不含附加字段)
        snapshot = dict(res)
        snapshot["report_html"] = html_path
        snapshot["report_json"] = json_path
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2, default=str)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_render_speedtest_html(res))
        return html_path, json_path
    except Exception:
        return None


def _render_iperf3_html(res):
    """渲染 iperf3 链路吞吐报告 HTML (内联 canvas 曲线, 完全离线可用)。"""
    ts_disp = (res.get("timestamp") or "")[:19].replace("T", " ")
    server = res.get("server", "—")
    # banner/sub 直接插入 HTML, 必须转义 (detail_rows 那路已有 _esc_html, 别双转义)
    server_html = _esc_html(str(server))
    port = res.get("port", 5201)
    duration = res.get("duration_s", 10)
    dl = res.get("download_mbps")
    ul = res.get("upload_mbps")
    dl_str = f"{dl:.1f}" if dl is not None else "失败"
    ul_str = f"{ul:.1f}" if ul is not None else "失败"
    dl_re = res.get("download_retransmits")
    ul_re = res.get("upload_retransmits")
    dl_err = res.get("download_error")
    ul_err = res.get("upload_error")

    down_intervals = res.get("download_intervals_mbps") or []
    up_intervals = res.get("upload_intervals_mbps") or []
    down_data = [[i + 1, v] for i, v in enumerate(down_intervals)]
    base_t = len(down_intervals)
    up_data = [[i + 1 + base_t, v] for i, v in enumerate(up_intervals)]
    data_js = json.dumps({"down": down_data, "up": up_data}, ensure_ascii=False)

    detail_rows = [
        ("服务器", f"{server}:{port}"),
        ("单方向时长", f"{duration} s"),
        ("下载 (到服务器)", dl_str + " Mbps" + (f" · 重传 {dl_re}" if dl_re else "")),
        ("上传 (到服务器)", ul_str + " Mbps" + (f" · 重传 {ul_re}" if ul_re else "")),
        ("下载备注", dl_err or "正常"),
        ("上传备注", ul_err or "正常"),
    ]
    detail_html = "\n".join(
        f"      <tr><td>{k}</td><td>{_esc_html(str(v))}</td></tr>" for k, v in detail_rows)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetPulse iperf3 链路吞吐报告</title>
<style>
  {_BRAND_HEADER_CSS}
  body {{ font-family: "Microsoft YaHei", "Segoe UI", sans-serif; margin: 0; background: #eef2f6; color: #1c2430; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 28px 20px 48px; }}
  h1 {{ font-size: 23px; margin: 0; font-weight: 600; }}
  h1 .dot {{ color: #0a84ff; margin-right: 6px; }}
  .sub {{ color: #7b8794; font-size: 12.5px; margin: 6px 0 22px; }}
  .banner {{ background: #fff7e6; border: 1px solid #ffe0a3; color: #8a5a00;
            border-radius: 12px; padding: 12px 16px; font-size: 13px; margin-bottom: 18px; }}
  .metric-row {{ display: flex; gap: 12px; margin-bottom: 12px; }}
  .metric {{ flex: 1; background: #fff; border-radius: 14px; padding: 18px 20px 14px;
             box-shadow: 0 1px 3px rgba(16,42,67,.08); border-top: 3px solid #d3dae2; }}
  .metric .label {{ color: #7b8794; font-size: 12px; margin-bottom: 4px; }}
  .metric .big {{ font-size: 40px; font-weight: 600; line-height: 1.12; letter-spacing: -1px; }}
  .metric .big .unit {{ font-size: 14px; color: #7b8794; font-weight: 400; }}
  .metric.down {{ border-top-color: #0a84ff; }} .metric.down .big {{ color: #0a84ff; }}
  .metric.up {{ border-top-color: #ff9500; }} .metric.up .big {{ color: #ff9500; }}
  .panel {{ background: #fff; border-radius: 14px; padding: 18px 20px; margin-bottom: 18px;
            box-shadow: 0 1px 3px rgba(16,42,67,.08); }}
  .panel h3 {{ margin: 0 0 14px; font-size: 15px; color: #1c2430; font-weight: 500;
               display:flex;align-items:center;gap:8px; }}
  .tag-tp {{ display:inline-block; padding:2px 9px; border-radius:5px;
    font-size:11px; font-weight:600; background:#e0e7ff; color:#4338ca; letter-spacing:.2px; }}
  canvas {{ width: 100%; height: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #f0f2f5; }}
  td:first-child {{ color: #7b8794; width: 160px; }}
  .legend {{ font-size: 12px; color: #7b8794; margin-top: 10px; }}
  .legend .sw {{ display: inline-block; width: 16px; height: 4px; border-radius: 2px;
                 margin: 0 6px 2px 14px; vertical-align: middle; }}
  .legend .sw:first-of-type {{ margin-left: 0; }}
  .footer {{ color: #a4aeb8; font-size: 12px; text-align: center; margin-top: 28px; }}
</style>
</head>
<body>
<div class="wrap">
  {_render_brand_header("iperf3 链路吞吐报告",
                        f"测试时间: {ts_disp} &nbsp;·&nbsp; 到服务器 {server_html}:{port}")}
  <div class="sub">链路吞吐实测 (TCP/UDP), 不含达标判定</div>

  <div class="banner">⚠️ iperf3 测量的是<b>到指定服务器 {server_html} 的链路吞吐</b>,
    不代表互联网宽带速率。服务器在内网时数值会远高于出口宽带, 属正常现象。</div>

  <div class="metric-row">
    <div class="metric down">
      <div class="label">下载 (到服务器)</div>
      <div class="big">{dl_str}<span class="unit"> Mbps</span></div>
      <div class="note">服务器 → 本机 (reverse)</div>
    </div>
    <div class="metric up">
      <div class="label">上传 (到服务器)</div>
      <div class="big">{ul_str}<span class="unit"> Mbps</span></div>
      <div class="note">本机 → 服务器</div>
    </div>
  </div>

  <div class="panel">
    <h3>吞吐速率曲线 <span class="tag-tp">Mbps · 每秒采样</span></h3>
    <canvas id="tpChart" width="840" height="280"></canvas>
    <div class="legend">
      <span class="sw" style="background:#0a84ff"></span>下载
      <span class="sw" style="background:#ff9500"></span>上传
    </div>
  </div>

  <div class="panel">
    <h3>测试详情</h3>
    <table>
{detail_html}
    </table>
  </div>

  <div class="footer">由 NetPulse 生成 · 链路吞吐实测数据, 不含达标判定</div>
</div>

<script>
var DATA = {data_js};
var multiLineChart = {_iperf3_chart_js()};
multiLineChart("tpChart", [
  {{data: DATA.down, color: "#0a84ff", fill: true, fillTop: "rgba(10,132,255,0.16)", fillBottom: "rgba(10,132,255,0.01)"}},
  {{data: DATA.up, color: "#ff9500", fill: true, fillTop: "rgba(255,149,0,0.16)", fillBottom: "rgba(255,149,0,0.01)"}}
]);
</script>
</body>
</html>"""


def _iperf3_chart_js():
    """复用 speedtest 报告的通用折线绘图函数 (返回 JS 源码字符串)。"""
    return """
function(ctxId, datasets) {
  var canvas = document.getElementById(ctxId);
  var ctx = canvas.getContext("2d");
  var W = canvas.width, H = canvas.height;
  var pad = {l: 56, r: 16, t: 16, b: 30};
  var iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
  ctx.clearRect(0, 0, W, H);
  var all = [];
  datasets.forEach(function(ds){ all = all.concat(ds.data); });
  if (all.length < 2) {
    ctx.fillStyle = "#999"; ctx.font = "13px sans-serif";
    ctx.fillText("无有效数据", pad.l, pad.t + 20); return;
  }
  var xmin = all[0][0], xmax = all[all.length-1][0];
  if (xmax === xmin) xmax = xmin + 1;
  var ymax = 0; all.forEach(function(p){ if (p[1] > ymax) ymax = p[1]; });
  if (ymax <= 0) ymax = 1; ymax = Math.ceil(ymax * 1.15);
  ctx.strokeStyle = "#e8ecf1"; ctx.lineWidth = 1;
  for (var i = 0; i <= 4; i++) {
    var gy = pad.t + (1 - i/4) * ih;
    ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke();
    ctx.fillStyle = "#98a2af"; ctx.font = "11px sans-serif"; ctx.textAlign = "right";
    ctx.fillText(Math.round(ymax * i / 4), pad.l - 6, gy + 4);
  }
  ctx.strokeStyle = "#d3dae2";
  ctx.beginPath(); ctx.moveTo(pad.l, pad.t); ctx.lineTo(pad.l, H - pad.b);
  ctx.lineTo(W - pad.r, H - pad.b); ctx.stroke();
  datasets.forEach(function(ds){
    if (ds.data.length < 2) return;
    var pts = ds.data.map(function(p){
      return [pad.l + (p[0]-xmin)/(xmax-xmin)*iw, pad.t + (1 - p[1]/ymax)*ih];
    });
    if (ds.fill) {
      var grad = ctx.createLinearGradient(0, pad.t, 0, H - pad.b);
      grad.addColorStop(0, ds.fillTop); grad.addColorStop(1, ds.fillBottom);
      ctx.fillStyle = grad; ctx.beginPath(); ctx.moveTo(pts[0][0], H - pad.b);
      pts.forEach(function(p){ ctx.lineTo(p[0], p[1]); });
      ctx.lineTo(pts[pts.length-1][0], H - pad.b); ctx.closePath(); ctx.fill();
    }
    ctx.strokeStyle = ds.color; ctx.lineWidth = 2; ctx.lineJoin = "round";
    ctx.beginPath();
    pts.forEach(function(p, i){ if (i === 0) ctx.moveTo(p[0], p[1]); else ctx.lineTo(p[0], p[1]); });
    ctx.stroke();
  });
  ctx.fillStyle = "#98a2af"; ctx.font = "11px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("0s", pad.l, H - 8);
  ctx.fillText(Math.round(xmax) + "s", W - pad.r, H - 8);
}"""


def _esc_html(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def save_iperf3_report(res):
    """保存 iperf3 链路吞吐报告 (HTML + JSON), 返回 (html_path, json_path)。"""
    try:
        day_dir = _report_dir()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(day_dir, f"iperf3_{stamp}.json")
        html_path = os.path.join(day_dir, f"iperf3_{stamp}.html")
        snapshot = dict(res)
        snapshot["report_html"] = html_path
        snapshot["report_json"] = json_path
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2, default=str)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_render_iperf3_html(res))
        return html_path, json_path
    except Exception:
        return None


class TCPConnectionAnalyzer:
    """TCP 连接数探测"""

    def __init__(self):
        self.name = "TCP 连接数检测"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在分析 TCP 连接...")
        code, out, _ = run_cmd("netstat -ano")
        connections = []
        for line in out.split("\n"):
            line = line.strip()
            if not line.startswith("TCP"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[1]
            remote = parts[2]
            state = parts[3]
            try:
                pid = int(parts[4])
            except ValueError:
                continue
            connections.append({
                "local": local,
                "remote": remote,
                "state": state,
                "pid": pid,
            })

        total = len(connections)
        by_state = Counter(c["state"] for c in connections)
        by_pid = Counter(c["pid"] for c in connections)

        # 获取 TOP 进程
        top_processes = []
        for pid, count in by_pid.most_common(10):
            name = get_process_name(pid)
            top_processes.append({"pid": pid, "name": name, "count": count})

        # 检查异常
        warnings = []
        if total > TCP_LIMIT_CRITICAL:
            warnings.append(f"TCP 连接数 {total} 超过临界值 {TCP_LIMIT_CRITICAL}，可能导致丢包/延迟")
        elif total > TCP_LIMIT_WARN:
            warnings.append(f"TCP 连接数 {total} 超过警告值 {TCP_LIMIT_WARN}")

        time_wait = by_state.get("TIME_WAIT", 0)
        if time_wait > total * 0.5 and total > 100:
            warnings.append(f"TIME_WAIT 连接 {time_wait} 占比过高 ({time_wait/total*100:.0f}%)，可能导致端口耗尽")

        close_wait = by_state.get("CLOSE_WAIT", 0)
        if close_wait > 50:
            warnings.append(f"CLOSE_WAIT 连接 {close_wait} 个，可能存在应用程序未正确关闭连接")

        established = by_state.get("ESTABLISHED", 0)
        if established > 1000:
            warnings.append(f"ESTABLISHED 连接 {established} 个，连接数偏高")

        # 检查系统端口范围限制
        code, port_range_out, _ = run_cmd("netsh int ipv4 show dynamicport tcp")
        port_range = "未知"
        start_port = None
        num_ports = None
        for line in port_range_out.split("\n"):
            if "Start Port" in line or "起始端口" in line:
                m = re.search(r":\s*(\d+)", line)
                if m:
                    start_port = int(m.group(1))
            if "Number of Ports" in line or "端口数" in line:
                m = re.search(r":\s*(\d+)", line)
                if m:
                    num_ports = int(m.group(1))
        if start_port is not None and num_ports is not None:
            port_range = f"{start_port}-{start_port + num_ports - 1} ({num_ports} 个)"

        assessment = "正常"
        if warnings:
            assessment = "异常" if total > TCP_LIMIT_CRITICAL else "需关注"

        self.results = {
            "total": total,
            "by_state": dict(by_state),
            "top_processes": top_processes,
            "warnings": warnings,
            "port_range": port_range,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"TCP 连接总数: {total}, 状态: {assessment}" +
                       (f" ({len(warnings)} 个警告)" if warnings else ""),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class MultiEgressDetector:
    """多外网出口检测"""

    def __init__(self):
        self.name = "多外网出口检测"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在检测外网出口...")
        issues = []
        routes = []

        # 1. 检查路由表中的默认路由
        if callback:
            callback("分析路由表...")
        code, out, _ = run_cmd("route print 0.0.0.0")
        default_routes = []
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                dest = parts[0]
                mask = parts[1]
                gateway = parts[2]
                interface = parts[3]
                metric = parts[4] if len(parts) > 4 else ""
                default_routes.append({
                    "destination": dest,
                    "mask": mask,
                    "gateway": gateway,
                    "interface": interface,
                    "metric": metric,
                })

        # 排除假网关 / VPN 虚拟接口占位 (ZeroTier 25.255.255.254 / Tailscale
        # 默认接口的 gateway 等)。这些地址要么不可达, 要么走 VPN 隧道, 都不算
        # 真正的"多出口"
        real_default = [
            r for r in default_routes
            if not _is_known_fake_gateway(r.get("gateway", ""))
            and not _is_vpn_interface(r.get("interface", ""))
        ]
        fake_default = [
            r for r in default_routes
            if _is_known_fake_gateway(r.get("gateway", ""))
            or _is_vpn_interface(r.get("interface", ""))
        ]

        if len(real_default) > 1:
            msg = f"检测到 {len(real_default)} 条真实默认路由"
            if fake_default:
                msg += f" (另有 {len(fake_default)} 条 VPN 占位假网关已忽略)"
            issues.append({
                "type": "multiple_default_routes",
                "severity": "warning",
                "message": msg,
                "detail": "多默认路由可能导致流量分担到不同出口，某条链路故障时可能影响部分流量"
            })
        elif fake_default:
            # 唯一真默认路由 + 假网关 -> 不报警, 改报 info
            # 关键: 优先显示接口名 (如 "ZeroTier One [xxx]" / "Default"),
            # 而非 gateway IP (VPN 虚拟接口的占位 gateway IP 可能恰好与真网关 IP
            # 相同, 把真网关 IP 标为假网关会让用户误以为真网关是假的)。
            def _fake_desc(r):
                iface = r.get('interface', '') or ''
                gw = r.get('gateway', '')
                metric = r.get('metric') or '?'
                if iface and iface != gw:
                    # 接口名 ≠ gateway IP, 用接口名 (如 "ZeroTier One [9f77...]")
                    return f"{_short_iface(iface, 36)} (gateway={gw}, metric={metric})"
                if iface:
                    # 接口名 == gateway IP, 退回到只显示 IP (避免重复)
                    return f"{gw}(metric={metric})"
                return f"{gw}(metric={metric})"
            fake_str = ", ".join(_fake_desc(r) for r in fake_default)
            # 识别常见 ZeroTier 25.255.255.254 情况, 提示更准确
            is_zerotier_fake = any(
                r["gateway"] == "25.255.255.254" for r in fake_default)
            if is_zerotier_fake:
                msg = f"检测到 ZeroTier 假网关 {fake_str} (设计行为, 无害)"
                detail = (f"ZeroTier 在 Windows 上为触发网络分类机制 (决定 Windows 防火墙规则) "
                          f"而插入的占位默认路由, 25.0.0.0/8 是英国国防部历史保留段, "
                          f"公网上不可能真实存在, 不影响真实流量。")
            else:
                msg = f"检测到 {len(fake_default)} 条 VPN 占位/虚拟接口默认路由 ({fake_str})"
                detail = (f"可能是 VPN 客户端 (Tailscale/WireGuard 等) "
                          f"为触发 Windows 网络分类或自身转发而插入的占位默认路由, "
                          f"不可达或走 VPN 隧道, 不影响真实流量。")
            detail += " 如需关闭可在对应 VPN 客户端关闭 'Allow Default Route' / 'Allow Global IPs' 等选项。"
            issues.append({
                "type": "fake_gateway_present",
                "severity": "info",
                "message": msg,
                "detail": detail,
            })

        # 2. 检测 VPN/虚拟适配器
        if callback:
            callback("检查 VPN/虚拟适配器...")
        adapters = get_network_adapters()
        vpn_adapters = []
        for adapter in adapters:
            desc = adapter.get("description", "").lower()
            name = adapter.get("name", "").lower()
            if any(kw in desc or kw in name for kw in
                   ["vpn", "virtual", "tap", "tun", "ppp", "wireguard", "openvpn", "sstp", "l2tp"]):
                vpn_adapters.append(adapter)

        if vpn_adapters:
            issues.append({
                "type": "vpn_detected",
                "severity": "info",
                "message": f"检测到 {len(vpn_adapters)} 个 VPN/虚拟适配器",
                "detail": "VPN 可能创建额外的网络出口，流量可能通过 VPN 隧道转发"
            })

        # 3. 检查公网 IP (多个服务并发, 冗余避免单一服务挂掉)
        if callback:
            callback("检测公网出口 IP...")
        public_ips = []
        ip_services = [
            ("https://qifu-api.baidubce.com/ip/local/geo/v1/district", "json"),
            ("https://myip.ipip.net", "text"),
            ("https://www.cip.cc", "text"),
        ]

        def _probe_pub(url, mode):
            try:
                req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
                resp = urlopen(req, timeout=4)
                raw = resp.read().decode("utf-8", "ignore")
                if mode == "json":
                    data = json.loads(raw)
                    return (data.get("data") or {}).get("ip", "")
                m = re.search(
                    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", raw)
                return m.group(1) if m else ""
            except Exception:
                return ""

        with ThreadPoolExecutor(max_workers=len(ip_services)) as ex:
            for ip in ex.map(lambda t: _probe_pub(*t), ip_services):
                if ip and ip not in public_ips:
                    public_ips.append(ip)

        # 4. 通过 tracert 到不同目标，比较第一跳 (并发)
        if callback:
            callback("比较到不同目标的路径...")
        first_hops = set()
        timed_out_targets = []
        tracert_targets = [("223.5.5.5", "AliDNS"),
                           ("114.114.114.114", "114DNS")]

        def _first_hop(target_ip, target_name):
            code, tracert_out, _ = run_cmd(
                f"tracert -d -h 3 -w 1000 {target_ip}", timeout=15)
            hops = parse_tracert_output(tracert_out)
            if not hops:
                return (target_ip, None)
            ip = hops[0]["ip"]
            return (target_ip, ip if ip != "*" else None)

        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(_first_hop, t, n) for t, n in tracert_targets]
            for f in as_completed(futs):
                target, hop = f.result()
                if hop:
                    first_hops.add(hop)
                else:
                    timed_out_targets.append(target)

        # 全超时也要单独报警, 避免被当 "单一出口"
        if timed_out_targets and not first_hops:
            issues.append({
                "type": "all_first_hops_timed_out",
                "severity": "warning",
                "message": f"到 {', '.join(timed_out_targets)} 的第一跳均无响应 (tracert 全部超时)",
                "detail": "可能是 ICMP 被本地/上游防火墙过滤, 或本地到第一跳的链路异常",
            })
        elif timed_out_targets:
            issues.append({
                "type": "some_first_hops_timed_out",
                "severity": "info",
                "message": f"到 {', '.join(timed_out_targets)} 的第一跳无响应",
                "detail": "ICMP 探测被部分目标过滤, 仅供参考",
            })

        if len(first_hops) > 1:
            issues.append({
                "type": "multiple_first_hops",
                "severity": "warning",
                "message": f"到不同目标的第一跳不一致: {', '.join(first_hops)}",
                "detail": "不同目标走不同网关，可能存在多出口或策略路由"
            })

        # 5. 检查每个出口的连通性 (并发 ping)
        if callback:
            callback("检测各出口连通性...")
        egress_status = []

        def _check_egress(route):
            gw = route["gateway"]
            iface = route.get("interface", "")
            # 跳过"假网关"占位 (ZeroTier 等 VPN 的不可达地址, ping 必 100% 丢,
            # 报故障会误导用户)。改成 info 标注
            if _is_known_fake_gateway(gw) or _is_vpn_interface(iface):
                # 区分两种情况给不同状态文案
                if _is_known_fake_gateway(gw):
                    reason = "VPN 占位 (假网关, 已跳过)"
                else:
                    reason = f"VPN 虚拟接口 ({iface}, 已跳过)"
                return {
                    "gateway": gw,
                    "interface": iface,
                    "metric": route["metric"],
                    "ping_loss_pct": None,
                    "ping_avg_ms": None,
                    "status": reason,
                    "_critical": False,
                }
            # wait_ms=3000 与系统默认接近, 避免 WiFi 网关忙时偶发 >1.5s 响应
            # 被误判为丢包 (旧版 wait_ms=1500 是误报根因)
            ping_result = ping_host(gw, count=10, timeout=25, wait_ms=3000)
            loss = ping_result["loss_pct"]
            # 三态判定 (参考 ExternalNetworkTester): ping 100% 丢包时用 TCP 兜底,
            # 区分"网关禁 ping"(实际可达) 与"网关不可达"(真故障), 避免误报
            if loss >= 100:
                tcp_ok, _, _ = _tcp_probe_multi(
                    gw, ports=(53, 80, 443, 8080), timeout=2.0)
                if tcp_ok:
                    status = "可达 (禁 ping, TCP 正常)"
                    critical = False
                else:
                    status = "故障"
                    critical = True
            elif loss == 0:
                status = "正常"
                critical = False
            elif loss < 50:
                status = f"丢包 {loss}%"
                critical = False
            else:
                status = "故障"
                critical = True
            return {
                "gateway": gw,
                "interface": route["interface"],
                "metric": route["metric"],
                "ping_loss_pct": ping_result["loss_pct"],
                "ping_avg_ms": ping_result["avg_ms"],
                "status": status,
                "_critical": critical,
            }

        with ThreadPoolExecutor(max_workers=min(4, len(default_routes))) as ex:
            for row in ex.map(_check_egress, default_routes):
                egress_status.append({
                    k: v for k, v in row.items() if k != "_critical"})
                if row["_critical"]:
                    issues.append({
                        "type": "egress_failure",
                        "severity": "critical",
                        "message":
                            f"出口网关 {row['gateway']} 可能故障 "
                            f"(丢包 {row['ping_loss_pct']}%)",
                        "detail": "该出口链路可能存在问题，建议检查物理连接或网络设备"
                    })

        multiple_egress = len(real_default) > 1 or len(vpn_adapters) > 0 or len(first_hops) > 1

        self.results = {
            "default_routes": default_routes,
            "vpn_adapters": vpn_adapters,
            "public_ips": public_ips,
            "first_hops": list(first_hops),
            "egress_status": egress_status,
            "issues": issues,
            "multiple_egress": multiple_egress,
            "timestamp": datetime.now().isoformat(),
            "summary": f"{'检测到多外网出口' if multiple_egress else '单一外网出口'}" +
                       (f", {len(issues)} 个问题" if issues else "，正常"),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


# --- 补充诊断模块 ---

class DNSTester:  # @deprecated v1.2.0 (B8): 已迁移到 probe_dns_v2 (SECTION 1e)
    """DNS 解析诊断"""

    def __init__(self):
        self.name = "DNS 解析诊断"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在测试 DNS 解析...")
        test_domains = ["www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com"]
        results = []

        # 系统当前 DNS
        system_dns = get_dns_servers()
        if callback:
            callback(f"系统 DNS: {', '.join(system_dns) if system_dns else '未检测到'}")

        # 测试每个 DNS 服务器 (多服务器并行, 组内域名串行, 结果保持提交顺序)
        all_dns = system_dns + [ip for ip, _ in DNS_SERVERS if ip not in system_dns]

        def _query(dns_ip, domain):
            dns_name = next(
                (name for ip, name in DNS_SERVERS if ip == dns_ip), "系统DNS")
            resolved, elapsed = _dns_query(dns_ip, domain, timeout=2.5)
            return {"dns_server": dns_ip, "dns_name": dns_name,
                    "domain": domain, "resolved_ip": resolved,
                    "time_ms": elapsed, "success": resolved is not None}

        tasks = [(d, dom) for d in all_dns for dom in test_domains]
        if callback:
            callback(f"DNS 测试 {len(tasks)} 次 (多服务器并行)...")
        with ThreadPoolExecutor(max_workers=min(8, len(all_dns))) as ex:
            for r in ex.map(lambda t: _query(*t), tasks):
                results.append(r)
        if callback:
            callback(f"DNS 测试完成: "
                     f"{sum(1 for r in results if r['success'])}/{len(results)} 成功")

        # 汇总
        success_count = sum(1 for r in results if r["success"])
        total_count = len(results)
        avg_time = sum(r["time_ms"] for r in results if r["success"]) / max(success_count, 1)

        # 检测 DNS 污染 (同一域名不同 DNS 返回不同结果)
        domain_ips = defaultdict(set)
        for r in results:
            if r["success"] and r["resolved_ip"]:
                domain_ips[r["domain"]].add(r["resolved_ip"])

        # 检测 DNS 劫持: 系统 DNS 对公网域名返回私有/保留 IP
        # (透明代理/DNS 劫持的明确信号 — 公网域名不应解析到内网地址)
        issues = []
        hijack_samples = []
        for r in results:
            if (r["success"] and r["resolved_ip"]
                    and r["dns_name"] == "系统DNS"):
                try:
                    ip_obj = ipaddress.ip_address(r["resolved_ip"])
                    if (ip_obj.is_private or ip_obj.is_loopback
                            or ip_obj.is_reserved):
                        hijack_samples.append((r["domain"], r["resolved_ip"]))
                except Exception:
                    pass
        dns_hijack = len(hijack_samples) > 0
        if dns_hijack:
            sample = ", ".join(f"{d}→{ip}" for d, ip in hijack_samples[:3])
            issues.append({
                "type": "dns_hijack",
                "severity": "critical",
                "message": f"系统 DNS 对公网域名返回私有 IP ({sample})",
                "detail": "可能存在透明代理/DNS 劫持, 系统 DNS 未返回真实公网解析结果",
            })

        # 解析不一致提示: 同一域名在不同 DNS 下返回多个不同 IP。
        # 注意 CDN 轮询 (按地域/运营商返回不同节点) 是正常现象, 因此只做
        # info 级提示且措辞保守, 不当作故障。
        inconsistent = [(d, len(ips)) for d, ips in domain_ips.items() if len(ips) >= 2]
        if inconsistent and not dns_hijack:
            sample = ", ".join(f"{d}({n} 个结果)" for d, n in inconsistent[:3])
            issues.append({
                "type": "dns_inconsistent",
                "severity": "info",
                "message": f"部分域名在不同 DNS 下解析结果不一致 ({sample})",
                "detail": "多为 CDN 按地域/运营商轮询 (正常现象); 若某 DNS 长期返回"
                          "固定异常 IP 而其它 DNS 正常, 可怀疑该 DNS 被污染",
            })

        assessment = "正常"
        if success_count < total_count * 0.5:
            assessment = "DNS 解析异常"
        elif avg_time > 100:
            assessment = "DNS 响应慢"
        if dns_hijack:
            assessment = "DNS 疑似劫持"

        # 按 DNS 服务器聚合: 报告主视图每个服务器只展示一行,
        # 而非把 服务器×域名 的全部原始记录 (28+ 条) 平铺出来。
        per_server = []
        for dns_ip in dict.fromkeys(r["dns_server"] for r in results):
            grp = [r for r in results if r["dns_server"] == dns_ip]
            ok = sum(1 for r in grp if r["success"])
            tot = len(grp)
            avg = sum(r["time_ms"] for r in grp if r["success"]) / max(ok, 1)
            st = "正常" if ok == tot else ("部分失败" if ok > 0 else "不可用")
            per_server.append({
                "dns_server": dns_ip,
                "dns_name": grp[0]["dns_name"],
                "ok": ok,
                "total": tot,
                "avg_ms": round(avg, 1),
                "status": st,
            })

        self.results = {
            "system_dns": system_dns,
            "assessment": assessment,
            "dns_hijack": dns_hijack,
            "success_count": success_count,
            "total_count": total_count,
            "avg_time_ms": round(avg_time, 1),
            "per_server": per_server,        # 聚合视图 (主表)
            "detail": results,               # 原始测试记录 (弱化的"详细测试记录")
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"DNS 测试: {success_count}/{total_count} 成功, 平均 {avg_time:.0f}ms"
                       + ("，疑似劫持" if dns_hijack else ""),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


def _probe_path_mtu(target):
    """二分查找 MTU (ICMP payload: MTU - 28)。

    与原实现的区别:
    - 区分「无信号」(超时/丢包) 与「太大」(DF 拒绝) 两种情形;
      原实现把超时一律当「太大」, 在 ICMP 被防火墙过滤的环境下
      会返回错误的 path_mtu (实际上是探测失败, 但被报告为正常)。
    - 多次无信号直接放弃, 返回 error 而非假数据。
    - 加入总探测次数上限, 防止边界死循环。

    v1.7.0 (PR-F0): 从 MTUDetector._measure_mtu 闭包提取为模块级函数,
    diagnose 的 MTUDetector 与盯障模式 (MonitorSession) 共用同一探测逻辑。
    """
    low, high = 576, 1472
    best_mtu = None
    ever_fits = False
    last_fits = False
    indeterminate_count = 0
    total_count = 0
    MAX_INDETERMINATE = 4
    MAX_TOTAL = 15

    while low <= high and total_count < MAX_TOTAL:
        mid = (low + high) // 2
        total_count += 1
        code, out, _ = run_cmd(
            f"ping -f -l {mid} -n 1 -w 2000 {target}", timeout=5)

        too_big = ("需要拆分数据包但是设置 DF" in out or
                   "Packet needs to be fragmented but DF set" in out or
                   " Frag" in out)
        fits = ("TTL=" in out or "回复" in out or "Reply" in out)
        no_signal = (
            "传输中过期" in out or "timed out" in out or
            "100% 丢失" in out or "100% loss" in out or
            "请求超时" in out or "Request timed out" in out or
            not out.strip() or code != 0
        )

        if too_big:
            high = mid - 1
            last_fits = False
        elif fits:
            best_mtu = mid
            ever_fits = True
            last_fits = True
            low = mid + 1
        elif no_signal:
            indeterminate_count += 1
            if indeterminate_count >= MAX_INDETERMINATE:
                break
            # 范围略缩, 避免边界死循环; 保守假设: 之前若 fits 倾向 +
            if last_fits:
                low = mid + 1
            else:
                high = mid - 1
        else:
            # 未知输出: 也算无信号
            indeterminate_count += 1
            if indeterminate_count >= MAX_INDETERMINATE:
                break
            if last_fits:
                low = mid + 1
            else:
                high = mid - 1

    if not ever_fits:
        return {
            "target": target,
            "error": (f"未收到任何 ICMP Echo Reply ({total_count} 次探测均无响应), "
                      f"无法测量 MTU (可能是 ICMP 被防火墙/网关过滤)"),
            "path_mtu": None,
            "max_payload": None,
            "fragmentation_risk": None,
            "indeterminate": True,
            "probes": total_count,
        }

    return {
        "target": target,
        "max_payload": best_mtu,
        "path_mtu": best_mtu + 28,
        "fragmentation_risk": best_mtu < 1472,
        "indeterminate_pct": round(
            indeterminate_count / total_count * 100, 1)
            if total_count else 0,
        "probes": total_count,
    }


class MTUDetector:
    """MTU 路径发现"""

    def __init__(self):
        self.name = "MTU 路径发现"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在检测路径 MTU...")
        gateway = get_default_gateway()
        targets = [gateway] if gateway else []
        targets.append("223.5.5.5")

        if callback:
            callback(f"MTU 检测 {len(targets)} 个目标 (并发)...")
        results = []
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as ex:
            for r in ex.map(_probe_path_mtu, targets):
                results.append(r)

        # 本地接口 MTU
        # 注意: 过滤回环口与无效值 (v1.9.3) — Windows 回环口 NlMtu=4294967295
        # 是设计值 (-1 无符号), 混进 local_mtus 会把规则 max()/证据链/指标卡
        # 全部带偏 (报告曾出现 "接口 4294967295")。同时标记默认路由出口接口
        # (egress), 供规则层用"真实承载流量的接口"对比路径 MTU。
        code, out, _ = run_ps(
            "Get-NetIPInterface -AddressFamily IPv4 | "
            "Where-Object {$_.ConnectionState -eq 'Connected'} | "
            "Select-Object InterfaceAlias, NlMtu | ConvertTo-Json"
        )
        egress_alias = ""
        try:
            _eg_mtu, egress_alias = _default_route_if_mtu()
        except Exception:
            pass
        local_mtus = []
        if out and out.strip():
            try:
                data = json.loads(out)
                if not isinstance(data, list):
                    data = [data]
                for item in data:
                    alias = item.get("InterfaceAlias", "") or ""
                    try:
                        v = int(item.get("NlMtu", 0) or 0)
                    except (TypeError, ValueError):
                        continue
                    if v < _MTU_VALID_MIN or v > _MTU_VALID_MAX:
                        continue
                    if "loopback" in alias.lower():
                        continue
                    local_mtus.append({
                        "interface": alias,
                        "mtu": v,
                        "egress": bool(egress_alias)
                                  and alias.lower() == egress_alias.lower(),
                    })
            except Exception:
                pass
        # 出口接口排最前 (指标卡/摘要默认取 local[0] 展示"本机 MTU")
        local_mtus.sort(key=lambda lm: (not lm.get("egress"),))

        # 评估
        issues = []
        for r in results:
            if r.get("error"):
                issues.append(f"到 {r['target']} 的 MTU 测量失败: {r['error']}")
                continue
            if r["path_mtu"] < 1500:
                issues.append(f"到 {r['target']} 的路径 MTU ({r['path_mtu']}) 小于标准 1500，可能导致分片")
        for lm in local_mtus:
            if lm["mtu"] < 1500 and lm["mtu"] > 0:
                issues.append(f"接口 {lm['interface']} 的 MTU ({lm['mtu']}) 小于 1500 (可能是 PPPoE/VPN)")

        self.results = {
            "path_mtus": results,
            "local_mtus": local_mtus,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"MTU 检测: {'存在分片风险' if issues else '正常'}" +
                       (f" ({len(issues)} 个问题)" if issues else ""),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class ARPAnalyzer:  # @deprecated v1.2.0 (B10): 已迁移到 probe_arp_v2 (SECTION 1e)
    """ARP 表分析 / 欺骗检测"""

    def __init__(self):
        self.name = "ARP 表分析"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在分析 ARP 表...")
        gateway = get_default_gateway()

        code, out, _ = run_cmd("arp -a")
        entries = []
        mac_to_ips = defaultdict(list)
        ip_to_mac = {}

        # Windows `arp -a` 会按接口分组重复输出同一 (IP,MAC,type) 条目
        # (如同时连 WiFi + 有线, 同一网段条目出现两次)。不去重会导致:
        #   - total_entries 重复计数
        #   - mac_to_ips 里同一 IP 重复 -> multi_ip_macs 误判"多 IP 同 MAC"
        # LoopDetector 已处理该问题, 这里保持一致。
        seen_entries = set()
        for line in out.split("\n"):
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()
                arp_type = m.group(3)
                key = (ip, mac, arp_type)
                if key in seen_entries:
                    continue
                seen_entries.add(key)
                entries.append({"ip": ip, "mac": mac, "type": arp_type})
                mac_to_ips[mac].append(ip)
                ip_to_mac[ip] = mac

        # 检测 ARP 欺骗
        issues = []
        if gateway:
            gw_mac = ip_to_mac.get(gateway)
            if not gw_mac:
                issues.append({
                    "type": "gateway_arp_missing",
                    "severity": "warning",
                    "message": f"ARP 表中未找到网关 {gateway} 的条目",
                    "detail": "可能尚未与网关通信，或 ARP 缓存已过期"
                })
            else:
                # 检查是否有其他 IP 也使用网关的 MAC。
                # 关键: 排除广播/组播/协议保留 MAC 对应的 IP, 否则像
                # "ff-ff-ff-ff-ff-ff 对应 5 个子网广播 IP" 这种正常条目会误报。
                same_mac_ips = [
                    ip for ip in mac_to_ips.get(gw_mac, [])
                    if ip != gateway
                    and not _is_broadcast_or_reserved_ip(ip)
                ]
                if len(same_mac_ips) > 2:
                    issues.append({
                        "type": "gateway_mac_shared",
                        "severity": "info",
                        "message": f"网关 MAC {gw_mac} 被 {len(same_mac_ips)} 个其他 IP 使用",
                        "detail": f"IP 列表: {', '.join(same_mac_ips[:5])}。可能是路由器/交换机的多个接口"
                    })

                # ARP 欺骗检测 (MAC 频繁变化) 未实现: 需要多次采样对比同一 IP 的
                # MAC 是否漂移。单次 arp -a 快照无法判断, 且正常场景 (DHCP 重连、
                # 多网卡轮询) 也会引起 MAC 变化, 误报风险高。留待 --arp-rescan 模式。

            # 检测 ARP 冲突 (同一 IP 多个 MAC — 从 ARP 表可能看不到)
            # 检查静态 ARP 条目: 排除广播/组播/协议保留 MAC
            # (Windows arp -a 会把 ff-ff-ff-ff-ff-ff 标记为 static, 是协议保留,
            #  不是用户配置的静态 ARP, 误报)
            static_entries = [e for e in entries if e["type"] == "static"]
            static_valid = [e for e in static_entries
                            if _is_valid_unicast_mac(e["mac"])]
            static_reserved = len(static_entries) - len(static_valid)
            if static_entries:
                # 真实看到的 static 总数 (含 Windows 把广播/组播也标成 static 的协议保留)。
                # 报告给用户的文案必须把这两层都说清楚, 否则 "发现 1 条静态 ARP"
                # 会让用户以为只有 1 条 static, 实际上 arp -a 里 N 条都标了 static,
                # 只是其中 N-1 条是协议保留, 过滤掉了。
                detail = (f"arp -a 共显示 {len(static_entries)} 条 static 类型记录, "
                          f"其中 {static_reserved} 条为广播/组播/协议保留 MAC "
                          f"(已忽略, 非用户配置), {len(static_valid)} 条为真实单播 MAC。"
                          f"静态 ARP 可以防止 ARP 欺骗，但也可能导致 IP 变更后无法通信")
                issues.append({
                    "type": "static_arp",
                    "severity": "info",
                    "message": (f"发现 {len(static_valid)} 条静态 ARP 记录"
                                f" (共 {len(static_entries)} 条 static, 已过滤 {static_reserved} 条协议保留)"),
                    "detail": detail
                })

        # 统计
        total_entries = len(entries)
        # unique_macs: 排除广播/组播/协议保留 MAC
        valid_macs = {m for m in mac_to_ips.keys() if _is_valid_unicast_mac(m)}
        unique_macs = len(valid_macs)
        # multi_ip_macs: 只统计有效 unicast MAC, 否则广播/组播 MAC
        # 关联到多个子网广播 IP 是正常现象, 误报"多 IP 同 MAC"
        multi_ip_macs = {
            mac: ips for mac, ips in mac_to_ips.items()
            if _is_valid_unicast_mac(mac) and len(ips) > 1
        }

        self.results = {
            "gateway": gateway,
            "gateway_mac": ip_to_mac.get(gateway),
            "entries": entries,
            "total_entries": total_entries,
            "unique_macs": unique_macs,
            "multi_ip_macs": multi_ip_macs,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"ARP 表: {total_entries} 条记录, {unique_macs} 个 MAC" +
                       (f", {len(issues)} 个问题" if issues else "，正常"),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class BufferbloatTester:
    """Bufferbloat 负载延迟检测"""

    def __init__(self):
        self.name = "Bufferbloat 检测"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在检测 Bufferbloat (负载下延迟)...")
        gateway = get_default_gateway()

        if not gateway:
            self.results = {"error": "无法获取网关地址"}
            return self.results

        # 1. 空闲延迟基线
        if callback:
            callback("测量空闲延迟基线...")
        idle_ping = ping_host(gateway, count=10, timeout=15)
        idle_rtt = idle_ping["avg_ms"]
        idle_jitter = idle_ping["jitter_ms"]

        # 2. 负载下延迟 (同时发起大量下载)
        if callback:
            callback("测量负载下延迟...")
        # 启动负载线程
        stop_event = threading.Event()
        load_threads = []
        load_progress = {"bytes": 0, "lock": threading.Lock()}

        def generate_load():
            """生成网络负载。

            旧版问题: 用国外测速源 + urlopen 完整文件, 国内访问极慢, 每个
            线程每次循环要等几秒到几十秒, 4 个线程一起也打不满带宽。
            更早版本用的清华/阿里镜像路径已下线 (实测 404 / 拒连), Cloudflare
            从国内只有 ~1Mbps, 都打不满链路; 现用实测在线的腾讯/华为镜像。
            每次循环多下一点 (4MB) 摊薄 TLS 握手开销, 让链路真正"打满"。
            """
            urls = [
                "https://mirrors.tencent.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
                "https://mirrors.huaweicloud.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            ]
            while not stop_event.is_set():
                for url in urls:
                    if stop_event.is_set():
                        return
                    r = _download_speed_test(
                        url, target_bytes=4 * 1024 * 1024,
                        overall_timeout=12, callback=None)
                    if r and r.get("downloaded_bytes"):
                        with load_progress["lock"]:
                            load_progress["bytes"] += r["downloaded_bytes"]

        # 启动 4 个负载线程
        for _ in range(4):
            t = threading.Thread(target=generate_load, daemon=True)
            t.start()
            load_threads.append(t)

        # 等待负载建立: 累计下载 ≥16MB 即认为链路已打满 (100M 链路约 1.5s,
        # 1Mbps 慢链路要 2 分钟, 由 10s 上限兜底)。主线程不直接测量吞吐,
        # 避免给探测本身加噪。
        if callback:
            callback("等待链路负载稳定...")
        load_stable_deadline = time.time() + 10
        while time.time() < load_stable_deadline:
            time.sleep(0.5)
            with load_progress["lock"]:
                if load_progress["bytes"] >= 16 * 1024 * 1024:
                    break
        with load_progress["lock"]:
            load_bytes = load_progress["bytes"]
        # 累计不足 4MB = 负载基本没建立 (测速源不可用), 结果不可信
        load_warning = load_bytes < 4 * 1024 * 1024

        # 在负载下 ping
        if callback:
            callback("采样负载下延迟...")
        loaded_ping = ping_host(gateway, count=15, timeout=20)
        loaded_rtt = loaded_ping["avg_ms"]
        loaded_jitter = loaded_ping["jitter_ms"]

        # 停止负载并 join, 避免 daemon 线程残留到下一模块
        stop_event.set()
        for t in load_threads:
            t.join(timeout=10)
        # 残留线程置为 None, 不再被引用 (daemon=True 时进程退出时也会被强杀)

        # 计算 Bufferbloat 等级
        # bloat 为负 (负载下延迟反而更低) 不应判为优秀, 而是"未恶化/无 Bufferbloat"
        bloat = loaded_rtt - idle_rtt
        if load_warning:
            grade = "无法判定 (负载未建立, 测速源不可用)"
        elif bloat < 5:
            grade = "A (优秀, 无 Bufferbloat)"
        elif bloat < 30:
            grade = "B (良好)"
        elif bloat < 60:
            grade = "C (一般)"
        elif bloat < 100:
            grade = "D (较差)"
        else:
            grade = "F (很差)"

        issues = []
        if load_warning:
            issues.append("测速源不可用, 未产生有效负载, 结果不可信")
        elif bloat > 100:
            issues.append(f"严重 Bufferbloat: 负载下延迟增加 {bloat:.0f}ms")
        elif bloat > 30:
            issues.append(f"存在 Bufferbloat: 负载下延迟增加 {bloat:.0f}ms")

        # summary 措辞: bloat<0 (噪声) 时不要显示"增加 -Xms"
        if bloat >= 5:
            bloat_desc = f"增加 {bloat:.0f}ms"
        elif bloat <= -5:
            bloat_desc = f"降低 {-bloat:.0f}ms (网络在负载下未恶化)"
        else:
            bloat_desc = "基本无变化"

        if load_warning:
            summary = (f"Bufferbloat: 测速源不可用，负载未建立 "
                       f"(累计仅 {load_bytes // 1024}KB)，结果不可信")
        else:
            summary = (f"Bufferbloat: 空闲 {idle_rtt:.0f}ms → 负载 {loaded_rtt:.0f}ms "
                       f"({bloat_desc}, {grade})")

        self.results = {
            "gateway": gateway,
            "idle_rtt_ms": idle_rtt,
            "idle_jitter_ms": idle_jitter,
            "loaded_rtt_ms": loaded_rtt,
            "loaded_jitter_ms": loaded_jitter,
            "bloat_ms": round(bloat, 1),
            "grade": grade,
            "load_bytes": load_bytes,
            "load_warning": load_warning,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class IPv6Tester:
    """IPv6 连通性检测"""

    def __init__(self):
        self.name = "IPv6 连通性检测"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在检测 IPv6 连通性...")
        issues = []

        # 1. 检查本机 IPv6 地址
        local_ipv6 = []
        code, out, _ = run_cmd("ipconfig")
        has_global_ipv6 = False
        has_link_local = False
        # 只收集真正的"本机 IPv6 地址"行 — 不能简单用 "IPv6" in line 匹配,
        # 否则 "IPv6 默认网关 / IPv6 Default Gateway" 行 (fe80:: 或全局地址)
        # 也会被当作本机地址, 导致 local_ipv6 列表污染、has_global_ipv6 误判
        ipv6_addr_prefixes = (
            "IPv6 地址", "临时 IPv6 地址", "本地链接 IPv6 地址",
            "IPv6 Address", "Temporary IPv6 Address", "Link-local IPv6 Address",
        )
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith(ipv6_addr_prefixes):
                # 形如 "IPv6 地址 . . . : 240e:xxx:xxx" 或带作用域 "fe80::1%12"
                m = re.search(r":\s*([0-9a-fA-F:]+)", line)
                if m:
                    addr = m.group(1)
                    # 去掉 %scope 后缀 (如 fe80::1%12 → fe80::1)
                    addr = addr.split("%")[0]
                    if addr.startswith("::1"):
                        continue
                    local_ipv6.append(addr)
                    if addr.startswith("fe80"):
                        has_link_local = True
                    else:
                        has_global_ipv6 = True

        # 2. 检查 IPv6 路由
        code, route_out, _ = run_cmd("route print ::/0")
        has_ipv6_route = "::/0" in route_out

        # 3. IPv6 连通性测试
        # 用 TCP 53 (DNS 服务) 而非 443 — 2400:3200::1 是阿里 DNS, 通常只开
        # 53, 测 443 会误判"IPv6 不可连通"。53 失败时 443 兜底。
        ipv6_connectivity = False
        ipv6_dns = False
        ipv6_target = "2400:3200::1"
        for port in (53, 443):
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((ipv6_target, port))
                s.close()
                ipv6_connectivity = True
                break
            except Exception:
                continue

        # 4. IPv6 DNS 解析
        try:
            socket.getaddrinfo("dns.alidns.com", None, socket.AF_INET6)
            ipv6_dns = True
        except Exception:
            ipv6_dns = False

        if not has_global_ipv6:
            issues.append("未检测到全局 IPv6 地址")
        if has_global_ipv6 and not ipv6_connectivity:
            # Windows `route print ::/0` 不显示 ISATAP/6to4 隧道的默认路由, 所以
            # has_ipv6_route=False 不一定是配置问题。实际能 ping 通 2400:: 等
            # 目的地址才算真正的 IPv6 可用, 这里用更准确的措辞
            if has_ipv6_route:
                issues.append("有 IPv6 路由但无法建立 IPv6 连接，可能是防火墙/MTU 问题")
            else:
                issues.append("有 IPv6 地址但当前无法通过 IPv6 上外网 "
                              "(本机配置了隧道方式的 IPv6, 系统命令查不到它的路由)。")
        if has_global_ipv6 and not ipv6_dns:
            issues.append("IPv6 DNS 解析失败")

        assessment = "不支持"
        if has_global_ipv6 and ipv6_connectivity:
            assessment = "IPv6 正常"
        elif has_global_ipv6:
            assessment = "IPv6 配置异常"
        elif has_link_local:
            assessment = "仅链路本地 IPv6"

        self.results = {
            "local_ipv6": local_ipv6,
            "has_global_ipv6": has_global_ipv6,
            "has_link_local": has_link_local,
            "has_ipv6_route": has_ipv6_route,
            "ipv6_connectivity": ipv6_connectivity,
            "ipv6_dns": ipv6_dns,
            "ipv6_target": ipv6_target,
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"IPv6: {assessment}",
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class RouteTableAnalyzer:  # @deprecated v1.2.0 (B9): 已迁移到 probe_route_v2 (SECTION 1e)
    """路由表异常分析"""

    def __init__(self):
        self.name = "路由表分析"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("正在分析路由表...")
        issues = []

        code, out, _ = run_cmd("route print")
        routes = []
        in_ipv4 = False
        for line in out.split("\n"):
            line = line.strip()
            if "IPv4 路由表" in line or "IPv4 Route Table" in line:
                in_ipv4 = True
                continue
            if "IPv6" in line:
                in_ipv4 = False
                continue
            if in_ipv4 and line:
                parts = line.split()
                if len(parts) >= 5 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    routes.append({
                        "destination": parts[0],
                        "mask": parts[1],
                        "gateway": parts[2],
                        "interface": parts[3],
                        "metric": parts[4],
                    })

        # 检查异常
        default_routes = [r for r in routes if r["destination"] == "0.0.0.0"]
        # 排除"假网关" / VPN 虚拟接口占位 (ZeroTier 25.255.255.254 / Tailscale
        # 默认接口的 gateway 等, 不可达或走 VPN 隧道, 不算真"多默认路由")
        real_default_routes = [
            r for r in default_routes
            if not _is_known_fake_gateway(r.get("gateway", ""))
            and not _is_vpn_interface(r.get("interface", ""))
        ]
        fake_default_routes = [
            r for r in default_routes
            if _is_known_fake_gateway(r.get("gateway", ""))
            or _is_vpn_interface(r.get("interface", ""))
        ]
        if len(real_default_routes) > 1:
            msg = f"多条默认路由 ({len(real_default_routes)} 条)"
            detail = "可能导致流量路径不确定"
            if fake_default_routes:
                # 提示用户: 这些不是真问题, 是 VPN 客户端的占位
                # 关键: 优先显示接口名, 避免把真网关 IP 误标为假网关
                def _fake_desc(r):
                    iface = r.get('interface', '') or ''
                    gw = r.get('gateway', '')
                    metric = r.get('metric') or '?'
                    if iface and iface != gw:
                        return f"{_short_iface(iface, 36)} (gateway={gw}, metric={metric})"
                    return f"{gw}(metric={metric})"
                fake_str = ", ".join(_fake_desc(r) for r in fake_default_routes)
                detail += f"。另有 {len(fake_default_routes)} 条 VPN 占位/虚拟接口已忽略: {fake_str}"
            issues.append({
                "type": "multiple_default",
                "severity": "warning",
                "message": msg,
                "detail": detail,
            })
        elif len(default_routes) > 1 and fake_default_routes:
            # 唯一真默认路由 + 一条或多条假网关 -> 不报警, 改报 info 提示
            def _fake_desc(r):
                iface = r.get('interface', '') or ''
                gw = r.get('gateway', '')
                metric = r.get('metric') or '?'
                if iface and iface != gw:
                    return f"{_short_iface(iface, 36)} (gateway={gw}, metric={metric})"
                return f"{gw}(metric={metric})"
            fake_str = ", ".join(_fake_desc(r) for r in fake_default_routes)
            # 识别常见 ZeroTier 25.255.255.254 情况, 提示更准确
            is_zerotier_fake = any(
                r["gateway"] == "25.255.255.254" for r in fake_default_routes)
            if is_zerotier_fake:
                msg = f"检测到 ZeroTier 假网关 {fake_str} (设计行为, 无害)"
                detail = (f"ZeroTier 在 Windows 上为触发网络分类机制 (决定 Windows 防火墙规则) "
                          f"而插入的占位默认路由, 25.0.0.0/8 是英国国防部历史保留段, "
                          f"公网上不可能真实存在, 不影响真实流量。")
            else:
                msg = f"检测到 {len(fake_default_routes)} 条 VPN 占位/虚拟接口默认路由 ({fake_str})"
                detail = (f"可能是 VPN 客户端 (Tailscale/WireGuard 等) "
                          f"为触发 Windows 网络分类或自身转发而插入的占位默认路由, "
                          f"不可达或走 VPN 隧道, 不影响真实流量。")
            detail += " 如需关闭可在对应 VPN 客户端关闭 'Allow Default Route' / 'Allow Global IPs' 等选项。"
            issues.append({
                "type": "fake_gateway_present",
                "severity": "info",
                "message": msg,
                "detail": detail,
            })

        # 检查异常路由 (目标为具体 IP 但掩码为 255.255.255.255 的大量主机路由)
        host_routes = [r for r in routes if r["mask"] == "255.255.255.255" and
                       r["destination"] != "127.0.0.1"]
        if len(host_routes) > 50:
            issues.append({
                "type": "too_many_host_routes",
                "severity": "info",
                "message": f"主机路由数量较多 ({len(host_routes)} 条)",
                "detail": "可能由 VPN 或虚拟化软件创建"
            })

        # 检查路由环路 (A 的网关是 B, B 的网关是 A)
        # 局限性: 路由表里 destination 是网段、gateway 是下一跳 IP, 下一跳 IP
        # 一般不会同时出现在 destination 中, 因此该判定在 Windows 上几乎不会
        # 命中 (保留作为极端配置的兜底, 不构成误报来源)。
        route_map = {r["destination"]: r["gateway"] for r in routes}
        for dest, gw in route_map.items():
            if gw in route_map and route_map[gw] == dest and dest != gw:
                issues.append({
                    "type": "route_loop",
                    "severity": "warning",
                    "message": f"疑似路由环路: {dest} -> {gw} -> {dest}",
                    "detail": "路由表存在 A↔B 互指网关的配置, 可能导致数据包循环"
                })

        # 检查无效路由 (网关不可达)
        gateway = get_default_gateway()
        if gateway:
            # 检查默认路由的网关是否在相同子网 (用真实 prefix length, 避免 /24 误判)
            local_ip = get_local_ip()
            if gateway and local_ip:
                try:
                    local_net = _get_local_subnet(local_ip)
                    if local_net is not None and \
                            ipaddress.IPv4Address(gateway) not in local_net:
                        issues.append({
                            "type": "gateway_not_in_subnet",
                            "severity": "warning",
                            "message": f"默认网关 {gateway} 不在本地子网 {local_net} 内",
                            "detail": "网关不在本地子网可能导致通信异常"
                        })
                except Exception:
                    pass

        self.results = {
            "routes": routes,
            "route_count": len(routes),
            "default_routes": default_routes,
            "host_routes": host_routes,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"路由表: {len(routes)} 条路由" +
                       (f", {len(issues)} 个问题" if issues else "，正常"),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


# ============================================================
# 端口连通性探测 (tcping / udpping)
# ============================================================

# 默认探测目标: 留空。端口探测必须由用户显式指定 (host:port), 不再有内置默认值。
# 原因: 内置 DNS 53 端口探测跟"外网检测"功能重叠, 且绝大多数用户实际想测的
#       是内网服务/特定业务端口, 默认值会误导。运行 `all` 时端口探测会从模块
#       列表里被排除; 运行 `port` 时 (菜单/CLI) 强制要求用户输入目标。
DEFAULT_PORT_TARGETS = []


# 端口范围探测时, 单次 spec 能展开多少个 (host, port) 元组的硬上限。
# 这个数独立于"总目标数 1000", 是防止 "host:1-65535" 这种单 spec 一次展开
# 65k 目标把内存/线程池打爆。65535 = 单 IP 全端口, 足够任何单 spec 场景。
_MAX_PORTS_PER_SPEC = 65535


def _parse_target(spec):
    """解析端口目标规格 -> 展开后的 (host, port) 列表; 非法返回 None。

    支持格式:
      - host:port           单端口 (例: 192.168.1.1:443)
      - host:port1,port2    多离散端口 (例: 223.5.5.5:80,443)
      - host:port1-port2    端口范围 (例: 10.0.0.1:1-1024)
      - host:p1,p2,p3-p4    混合 (例: a.com:22,80,8000-8100)
      - [ipv6]:port         IPv6 单端口 (例: [::1]:443)
      - [ipv6]:port1-port2  IPv6 范围 (例: [2400::1]:80-443)

    不支持 CIDR (按 Simon 拍板, 留作未来扩展)。

    返回:
      - [(host, port), ...]  成功 (可能为空, 实际不会空, 空说明 spec 解析失败)
      - None                  非法 spec (空字符串 / 解析失败 / 端口越界 / 范围倒序)
    """
    spec = (spec or "").strip()
    if not spec:
        return None

    # 拆 host 和 ports 部分: 最后一个 ':' 之前是 host, 之后是 ports
    # IPv6 用 [..] 包裹, 找 ']:' 分割
    if spec.startswith("["):
        m = re.match(r"^\[(.+)\]:(.+)$", spec)
        if not m:
            return None
        host, ports_str = m.group(1), m.group(2)
    else:
        # 单 host 形式, 最后一个 ':' 分割
        if ":" not in spec:
            return None
        # 避免主机名含 ':' (罕见, 一般 host 只有数字 IP 或域名)
        idx = spec.rfind(":")
        host, ports_str = spec[:idx], spec[idx + 1:]

    if not host or not ports_str:
        return None

    # 解析 ports 部分: 逗号分隔, 每项是 port 或 port-port
    port_items = [p.strip() for p in ports_str.split(",") if p.strip()]
    if not port_items:
        return None

    ports = []
    for item in port_items:
        # 单端口
        if "-" not in item:
            try:
                p = int(item)
            except ValueError:
                return None
            if not (1 <= p <= 65535):
                return None
            ports.append(p)
            continue
        # 范围 port1-port2
        rng = item.split("-", 1)
        if len(rng) != 2:
            return None
        try:
            lo, hi = int(rng[0]), int(rng[1])
        except ValueError:
            return None
        if not (1 <= lo <= 65535) or not (1 <= hi <= 65535):
            return None
        if lo > hi:
            return None   # 倒序不合法, 让用户写对
        ports.extend(range(lo, hi + 1))

    # 单 spec 展开上限保护 (防御 "host:1-65535" 一次展 65k)
    if len(ports) > _MAX_PORTS_PER_SPEC:
        return None

    return [(host, p) for p in ports]


def _prompt_for_port_targets():
    """交互式询问端口探测目标。返回 (targets_list, proto, count) 或 None (用户取消)。

    优化: 一行输入目标, 协议和次数用默认值 (tcp/4), 不再逐项询问;
    需要改时在目标后加 /udp 或 /次数, 如 192.168.1.1:443/8。

    用法: 交互菜单选 port, 或 CLI `port` 不带 --port-target 时调用。
    非 TTY 场景不应调用本函数 (调用方需先 sys.stdout.isatty() 判断)。
    """
    print(_c("  端口探测 (格式: HOST:PORT, 例: 192.168.1.1:443)", C_YELLOW))
    print(_c("  可选后缀: /udp 改 UDP, /N 改采样次数, 例: 8.8.8.8:53/udp/8", C_GRAY))
    print(_c("  默认: TCP 协议, 采样 4 次", C_GRAY))
    try:
        spec = input(_c("  目标 > ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not spec:
        return None
    # 解析可选后缀: /udp, /N (次数), /udp/N
    proto = "tcp"
    cnt = 4
    parts = spec.replace("，", ",").split("/")
    spec = parts[0].strip()
    for suffix in parts[1:]:
        suffix = suffix.strip().lower()
        if suffix in ("tcp", "udp", "both"):
            proto = suffix
        elif suffix.isdigit():
            cnt = max(1, int(suffix))
    # 解析目标列表 (逗号分隔)
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    valid = []
    expanded_count = 0
    for p in parts:
        parsed = _parse_target(p)
        if parsed:
            valid.append(p)
            expanded_count += len(parsed)
        else:
            print(_c(f"  ! 忽略非法目标: {p}", C_YELLOW))
    if not valid:
        print(_c("  没有合法目标, 已取消端口探测。", C_YELLOW))
        return None
    if expanded_count > 1:
        print(_c(f"  → 共 {expanded_count} 个目标, {proto.upper()}, 采样 {cnt} 次", C_GRAY))
    return valid, proto, cnt


def _prompt_for_iperf3():
    """交互式询问 iperf3 服务器地址。返回 (host, port) 或 None。

    优化: 直接问地址, 回车=跳过 (不再先问是否配置)。

    iperf3 是独立模块: 测到指定服务器的链路吞吐 (非互联网宽带), 需要部署
    iperf3 服务器 (通常在出口网关/IDC/内网)。不提供服务器则模块明确报缺服务器,
    不会回退成宽带测速 (两者已彻底分离)。

    用法: 交互菜单选 iperf3 模块, 且 CLI 未传 --iperf3-server 时调用。
    非 TTY 场景不应调用 (调用方需先 sys.stdout.isatty() 判断)。
    """
    print(_c("  iperf3 链路吞吐测试 (需自备服务器, 通常在出口/IDC)", C_YELLOW))
    print(_c("  直接回车=跳过 (该模块将提示缺少服务器)", C_GRAY))
    try:
        spec = input(_c("  iperf3 server (HOST 或 HOST:PORT, 缺省 :5201) > ",
                        C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not spec:
        return None
    # 解析 host:port
    if ':' in spec:
        host, _, port_s = spec.rpartition(':')
        port = int(port_s) if port_s.isdigit() else 5201
    else:
        host = spec
        port = 5201
    if not host:
        print(_c("  ! server 为空, 已跳过 iperf3", C_YELLOW))
        return None
    return (host, port)


def _prompt_for_web_targets(input_fn=None):
    """交互式询问网页体检追加目标 (v1.9.6 菜单入口, 对应 --web-target)。

    返回 URL 列表 (空 = 不追加)。默认 3 站 + 追加 ≤5 = 模块上限 8
    (WebPageTester.MAX_TARGETS), 超出截断并提示。
    非 TTY 场景不应调用本函数 (调用方需先 sys.stdout.isatty() 判断)。
    """
    input_fn = input_fn or input
    print(_c("  网页体检: 默认检测 3 个国内大站 (QQ/百度/阿里云)。", C_YELLOW))
    print(_c("  客户指定的站点 (如 OA/CRM) 可在此追加。", C_GRAY))
    try:
        spec = input_fn(_c("  追加体检站点 [Enter=不追加 / 完整URL, 逗号分隔最多5个] > ",
                           C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return []
    if not spec:
        return []
    urls = [u.strip() for u in spec.replace("，", ",").split(",") if u.strip()]
    valid = []
    for u in urls:
        if u.startswith(("http://", "https://")):
            valid.append(u)
        else:
            print(_c(f"  ! 忽略非法目标 (须 http:// 或 https:// 开头): {u}", C_YELLOW))
    if len(valid) > 5:
        print(_c("  ! 追加目标超过 5 个 (默认 3 站 + 追加 5 = 模块上限 8), "
                 "只保留前 5 个", C_YELLOW))
        valid = valid[:5]
    if valid:
        print(_c(f"  → 网页体检追加 {len(valid)} 个目标", C_GRAY))
    return valid


def _prompt_for_speedtest_node(input_fn=None):
    """交互式询问测速节点 (v1.9.6 菜单入口, 对应 --speedtest-node)。

    返回输入原文 (Ookla 数字 ID 或上行节点 host:port) 或 None=不换。
    解析与写入由调用方完成 (与 CLI --speedtest-node 的写入逻辑保持一致)。
    非 TTY 场景不应调用本函数 (调用方需先 sys.stdout.isatty() 判断)。
    """
    input_fn = input_fn or input
    cur = SPEEDTEST_CONFIG.get("ookla_server_id") or OOKLA_DEFAULT_SERVER_ID
    print(_c(f"  当前 Ookla 测速节点 ID: {cur} (默认 3633=上海电信)。", C_YELLOW))
    try:
        spec = input_fn(_c("  换测速节点? [Enter=不换 / 服务器ID 或 host:port, "
                           "如 5396=北京联通] > ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return spec or None


def _prompt_for_iperf3_mode(input_fn=None):
    """iperf3 服务器已具备时追问测速口径 (v1.9.6 菜单入口, 对应 --iperf3-udp)。

    返回 "udp" (UDP 抖动/丢包口径) 或 None (=默认 TCP 吞吐)。
    非 TTY 场景不应调用本函数 (调用方需先 sys.stdout.isatty() 判断)。
    """
    input_fn = input_fn or input
    try:
        ans = input_fn(_c("  测速口径? [Enter=TCP吞吐 / u=UDP抖动丢包(语音游戏口径)] > ",
                          C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return "udp" if ans.startswith("u") else None


class PortProbeTester:
    """端口连通性探测: 对每个 host:port 发起 TCP/UDP 探测 (类 tcping / udpping)。

    - TCP: 三次握手成功即「开放」; ConnectionRefused 即「关闭」(可达但无服务);
           超时无响应即「过滤」(可能被防火墙丢弃)。
    - UDP: 按协议发协议感知探针 (DNS=53/NTP=123/SSDP=1900/mDNS=5353),
           收到回包即「开放」; ConnectionRefused (ICMP unreachable) 即「关闭」;
           其它端口回退到 1 字节空载荷, 超时即「无响应」(UDP 无连接,
           开放或被过滤均可能无回包, 无法严格区分, 故标注为「无响应」)。
    每个目标做多次采样, 统计平均/最小/最大 RTT 与丢包。
    """

    # 单次探测目标数硬上限 (避免无意 DoS / 探测风暴)
    DEFAULT_MAX_TARGETS = 1000
    # 整个端口探测模块总时长上限 (秒), 0 = 不限
    DEFAULT_MAX_TOTAL_TIME = 60.0
    # 默认并发度: 同时探测多少个 (host, port) 目标
    DEFAULT_MAX_CONCURRENCY = 8

    def __init__(self, targets=None, proto="tcp", count=4,
                 max_targets=DEFAULT_MAX_TARGETS, force=False,
                 max_total_time=DEFAULT_MAX_TOTAL_TIME,
                 max_concurrency=DEFAULT_MAX_CONCURRENCY):
        self.name = "端口探测"
        self.results = {}
        self.targets = targets or DEFAULT_PORT_TARGETS
        self.proto = (proto or "tcp").lower()
        self.count = max(1, int(count))
        self.max_targets = max(1, int(max_targets))
        self.force = bool(force)
        self.max_total_time = max(0.0, float(max_total_time))
        # 并发度: 1 = 串行; 8 = 默认; 上限 64 (防 OS socket FD 爆掉)
        self.max_concurrency = max(1, min(64, int(max_concurrency)))
        self._start_time = None

    def _time_left(self):
        """返回剩余可用时间 (秒); 0 或负表示已超时。max_total_time=0 时不限。"""
        if self.max_total_time <= 0 or self._start_time is None:
            return float("inf")
        return self.max_total_time - (time.monotonic() - self._start_time)

    def _resolve(self, host):
        """解析主机名 -> (ip, family, 错误); family: socket.AF_INET / AF_INET6。"""
        try:
            infos = socket.getaddrinfo(host, None)
            infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
            fam, _, _, _, sockaddr = infos[0]
            return sockaddr[0], fam, None
        except Exception as e:
            return None, None, str(e)

    def _udp_probe(self, port):
        """根据端口号构造协议感知 UDP 探针, 返回 (payload, expect_reply, probe_name)。

        与旧版的差异: 旧版所有端口都发 1 字节空载荷, DNS/SNMP 等服务收到会
        丢弃, 导致 UDP 探测几乎全部被标"无响应", 用户看不出是服务挂了还是
        探针格式不对。改为按协议发合法请求, 命中率显著提升。
        """
        if port == 53:  # DNS: 标准 A 查询 (baidu.com, RD=1)
            header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            qname = (b"\x05" b"baidu" b"\x03" b"com" b"\x00")
            question = qname + struct.pack(">HH", 1, 1)  # A, IN
            return header + question, True, "DNS"
        if port == 123:  # NTP v3 client
            return b"\x1b" + b"\x00" * 47, True, "NTP"
        if port == 1900:  # SSDP M-SEARCH
            return (b"M-SEARCH * HTTP/1.1\r\n"
                    b"HOST: 239.255.255.250:1900\r\n"
                    b'MAN: "ssdp:discover"\r\n'
                    b"MX: 1\r\nST: ssdp:all\r\n\r\n"), True, "SSDP"
        if port == 5353:  # mDNS PTR query
            header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
            qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
            question = qname + struct.pack(">HH", 12, 1)  # PTR, IN
            return header + question, True, "mDNS"
        # 其它端口: 1 字节空载荷, 几乎肯定无回包
        return b"\x00", False, "raw"

    def _probe_one(self, host, port, proto):
        ip, fam, rerr = self._resolve(host)
        row = {
            "proto": proto.upper(),
            "host": host,
            "port": port,
            "resolved_ip": ip or "—",
            "status": "错误",
            "rtt_ms": "—",
            "loss": f"{self.count}/{self.count}",
            "error": "",
        }
        if ip is None:
            row["error"] = rerr or "主机解析失败"
            return row

        # 协议感知探针 (UDP 时)
        udp_payload = b"\x00"
        udp_probe_name = "raw"
        if proto == "udp":
            udp_payload, _, udp_probe_name = self._udp_probe(port)
            row["probe"] = udp_probe_name

        timeout = 3.0
        rtts = []
        c_open = c_closed = c_reply = c_filtered = c_err = 0
        last_err = None
        for _ in range(self.count):
            if proto == "tcp":
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.settimeout(timeout)
                t0 = time.perf_counter()
                try:
                    s.connect((ip, port))
                    rtts.append((time.perf_counter() - t0) * 1000.0)
                    c_open += 1
                except socket.timeout:
                    c_filtered += 1
                except ConnectionRefusedError:
                    rtts.append((time.perf_counter() - t0) * 1000.0)
                    c_closed += 1
                except OSError as e:
                    c_err += 1
                    last_err = str(e)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
            else:  # udp
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                t0 = time.perf_counter()
                try:
                    s.sendto(udp_payload, (ip, port))
                    s.recvfrom(1024)
                    rtts.append((time.perf_counter() - t0) * 1000.0)
                    c_reply += 1
                except socket.timeout:
                    c_filtered += 1
                except ConnectionRefusedError:
                    # 部分 OS 收到 ICMP port unreachable 后, 下一次 sendto/recvfrom
                    # 会以 ConnectionRefusedError 形式告知
                    c_closed += 1
                except ConnectionResetError:
                    # Windows: ICMP port unreachable 到达后, 下次 sendto/recvfrom
                    # 抛 WinError 10054 (ConnectionResetError)
                    c_closed += 1
                except OSError as e:
                    # 其它 OS 错误: 可能是网络不可达 (10051) 等, 算作错误
                    c_err += 1
                    last_err = str(e)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

        # 状态判定
        if c_open > 0:
            status = "开放"
        elif proto == "udp" and c_reply > 0:
            status = "开放"
        elif c_closed > 0:
            status = "关闭"
        elif c_filtered > 0:
            status = "无响应" if proto == "udp" else "过滤"
        else:
            status = "错误"

        if status == "错误":
            row["error"] = last_err or "探测失败"

        if rtts:
            avg = sum(rtts) / len(rtts)
            mn, mx = min(rtts), max(rtts)
            row["rtt_ms"] = f"{avg:.1f}  (min {mn:.1f} / max {mx:.1f})"
        timed = c_open + c_closed + c_reply
        row["loss"] = f"{self.count - timed}/{self.count}"
        row["status"] = status
        return row

    def detect(self, callback=None):
        if callback:
            callback(f"正在探测端口 ({self.proto.upper()}) ...")
        protos = ["tcp", "udp"] if self.proto == "both" else [self.proto]
        targets = []
        skipped = []
        if not self.targets:
            # 端口探测必须由用户显式提供目标, 不再有内置默认
            self.results = {
                "proto": self.proto.upper(),
                "probe_count": self.count,
                "targets": [],
                "issues": [{
                    "type": "port_no_targets",
                    "severity": "warning",
                    "message": "未提供端口探测目标",
                    "detail": "请用 --port-target host:port 指定 (可多次或逗号分隔); "
                              "菜单/CLI 选 port 时也会交互式询问"
                }],
                "assessment": "未提供目标",
                "timestamp": datetime.now().isoformat(),
                "summary": "端口探测: 未提供目标 (需用 --port-target 指定)"
            }
            if callback:
                callback(self.results["summary"])
            return self.results
        # 先把所有 spec 解析成 (host, port) 列表, 不实际探测
        expanded = []  # [(spec, host, port), ...]
        # 记开始时间, 用于 max_total_time 兜底
        self._start_time = time.monotonic()
        for spec in self.targets:
            # 总时长兜底: 解析阶段先检查, 但通常这一步极快, 实际超时发生在 _probe_one
            if self._time_left() <= 0 and not self.force:
                skipped.append(spec)
                continue
            parsed = _parse_target(spec)
            if not parsed:
                skipped.append(spec)
                continue
            for h, p in parsed:
                expanded.append((spec, h, p))

        # 目标数限流: 范围展开后总数 > max_targets 时阻止 (除非 force=True)
        # 注意: 限流检查在 _probe_one 之前, 否则探测大量端口会先执行造成卡顿
        n_total = len(expanded) * len(protos)
        if n_total > self.max_targets and not self.force:
            self.results = {
                "proto": self.proto.upper(),
                "probe_count": self.count,
                "targets": [],
                "specs": list(self.targets),
                "expanded_count": n_total,
                "max_targets": self.max_targets,
                "issues": [{
                    "type": "too_many_targets",
                    "severity": "warning",
                    "message": (f"展开后目标数 {n_total} 超过上限 {self.max_targets} "
                                f"(已取消探测, 防止无意探测风暴/DoS)"),
                    "detail": (f"原始 spec: {', '.join(self.targets)}\n"
                               f"展开后共 {n_total} 个 host:port 目标"
                               f"{(' × 2 协议' if len(protos) > 1 else '')}。"
                               f"如确认要探测这么多端口, 加 --port-force 重试。")
                }],
                "assessment": f"目标数 {n_total} 超限, 已取消",
                "timestamp": datetime.now().isoformat(),
                "summary": f"端口探测: 目标数 {n_total} 超过 {self.max_targets}, 已取消 (--port-force 强制执行)",
            }
            if callback:
                callback(self.results["summary"])
            return self.results

        # 通过限流, 实际探测 (内部并发, max_concurrency worker)
        targets = []
        timed_out_specs = []  # 因总时长超时被跳过的 spec
        # 估算单个目标最坏耗时 (count 次采样 × 3s socket timeout + DNS 解析)
        worst_case_per_target = self.count * 3.0 + 1.0

        # 把 expanded 展平成 (spec, h, p, pr) flat list, 保留原始顺序索引
        # 用于探测完成后按原顺序排回 (并发完成顺序会乱)
        probes = []  # [(spec, h, p, pr, flat_idx), ...]
        flat_idx = 0
        for spec, h, p in expanded:
            if self._time_left() <= worst_case_per_target and not self.force:
                timed_out_specs.append(spec)
                continue
            for pr in protos:
                if self._time_left() <= worst_case_per_target and not self.force:
                    timed_out_specs.append(spec)
                    break
                probes.append((spec, h, p, pr, flat_idx))
                flat_idx += 1

        # 并发探测: ThreadPoolExecutor 跑 probes, 结果存到 results_by_idx
        results_by_idx = [None] * len(probes)
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as ex:
            future_to_idx = {}
            for spec, h, p, pr, idx in probes:
                fut = ex.submit(self._probe_one, h, p, pr)
                future_to_idx[fut] = idx
            for fut in as_completed(future_to_idx):
                idx = future_to_idx[fut]
                try:
                    results_by_idx[idx] = fut.result()
                except Exception as e:
                    # 探测异常 (不应该发生, _probe_one 内部都 try 了) 兜底
                    spec, h, p, pr, _ = probes[idx]
                    results_by_idx[idx] = {
                        "proto": pr.upper(), "host": h, "port": p,
                        "resolved_ip": "—", "status": "错误",
                        "rtt_ms": "—", "loss": f"{self.count}/{self.count}",
                        "error": str(e),
                    }

        # 按原始 flat_idx 顺序还原, 这样报告里 targets 列表按 (spec, host, port) 顺序展示
        targets = [r for r in results_by_idx if r is not None]

        issues = []
        for t in targets:
            if t["status"] == "开放":
                continue
            sev = "critical" if t["status"] == "错误" else "warning"
            msg = f"{t['proto']} {t['host']}:{t['port']} {t['status']}"
            if t.get("error"):
                msg += f" ({t['error']})"
            issues.append({
                "type": "port_" + t["status"],
                "severity": sev,
                "message": msg,
                "detail": f"解析IP: {t['resolved_ip']}",
            })

        total = len(targets)
        open_n = sum(1 for t in targets if t["status"] == "开放")
        if total == 0:
            assessment = "未提供有效目标"
        elif open_n == total:
            assessment = "全部端口开放"
        else:
            assessment = f"{open_n}/{total} 端口开放, {total - open_n} 个未开放/不可达"
        proto_lbl = {"tcp": "TCP", "udp": "UDP", "both": "TCP+UDP"}[self.proto]

        self.results = {
            "proto": proto_lbl,
            "probe_count": self.count,
            "targets": targets,
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"端口探测({proto_lbl}): {open_n}/{total} 开放",
        }
        if skipped:
            self.results["skipped"] = skipped
        # 总时长超时提示: 让用户知道探测被中途截断, 而不是"漏了"
        if timed_out_specs:
            self.results["timed_out_specs"] = timed_out_specs
            self.results["max_total_time"] = self.max_total_time
            self.results["summary"] += (
                f" (超时, 跳过 {len(timed_out_specs)} 个 spec, "
                f"--port-timeout 提高)"
            )
            issues.append({
                "type": "port_total_timeout",
                "severity": "warning",
                "message": (f"端口探测总时长超过 {self.max_total_time}s 限制, "
                            f"跳过 {len(timed_out_specs)} 个 spec"),
                "detail": (f"已超时 spec: {', '.join(timed_out_specs)}\n"
                           f"如需探测全部目标, 加 --port-timeout 300 (秒) 重试。")
            })
            self.results["issues"] = issues
        if callback:
            callback(self.results["summary"])
        return self.results


# ============================================================
# 局域网设备扫描 + TCP 传输质量统计
# ============================================================

# 常见 MAC OUI 厂商前缀 (前 3 字节, 大写无分隔)
_OUI_VENDORS = {
    "001B21": "Intel", "001E10": "Intel", "A4D1D2": "Intel",
    "002500": "Apple", "F8E903": "Apple", "EC55F9": "Apple", "ACDE48": "Apple",
    "DC2132": "Huawei", "00E0FC": "Huawei", "4C1FCC": "Huawei", "886639": "Huawei",
    "2824E2": "Xiaomi", "6464A4": "Xiaomi", "8C16D3": "Xiaomi", "F81A67": "Xiaomi",
    "001372": "Cisco", "001F9E": "Cisco", "005056": "VMware",
    "080027": "VirtualBox", "001C42": "Parallels", "0050C2": "TUN/TAP",
    "F46D04": "TP-Link", "50C7BF": "TP-Link", "14CC20": "TP-Link",
    "C80E14": "Realtek", "00E04C": "Realtek", "0C8226": "Realtek",
    "0021CC": "D-Link", "00179A": "D-Link",
    "002608": "Tenda", "C83A35": "Tenda", "B0D5CC": "Tenda",
    "001A11": "Google", "FCE283": "Google",
    "001599": "Tuya", "1027D0": "Espressif", "8C4B14": "Espressif",
}


def _oui_vendor(mac):
    """根据 MAC 地址前 3 字节识别厂商, 未匹配返回空串。"""
    if not mac:
        return ""
    prefix = mac.replace("-", "").replace(":", "").upper()[:6]
    return _OUI_VENDORS.get(prefix, "")


# ============================================================
# 在线 OUI 补查 (mac.bmcx.com)
# 本地表仅覆盖约 30 个常见前缀, 覆盖面极小; 未命中时按 OUI 在线查询,
# 从页面 "组织名称" 表格解析厂商名。收录的 MAC 返回 200 + 表格,
# 未收录返回 404。OUI 级缓存避免同前缀设备重复请求。
# ============================================================
_OUI_ONLINE_CACHE = {}          # prefix6 -> vendor ("" = 已确认未收录, 不再重复请求)
_OUI_ONLINE_LOCK = threading.Lock()
_BMCX_TIMEOUT = 6               # 单次查询超时 (秒)
_BMCX_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def _oui_vendor_online(mac):
    """按 MAC 在线查询 mac.bmcx.com 解析厂商; 未收录/失败返回空串。

    - 200 + 组织名称   -> 缓存厂商名
    - 404 (未收录)     -> 缓存空串, 不再重查
    - 网络异常         -> 不缓存 (下次可重试)
    """
    if not mac:
        return ""
    prefix = mac.replace("-", "").replace(":", "").upper()[:6]
    if prefix in _OUI_ONLINE_CACHE:
        return _OUI_ONLINE_CACHE[prefix]
    vendor = ""
    cached = False
    try:
        url = f"https://mac.bmcx.com/{mac}__mac/"
        with _urlopen_with_proxy(url, timeout=_BMCX_TIMEOUT, ua=_BMCX_UA) as resp:
            status = getattr(resp, "status", 200)
            if status == 404:
                cached = True  # 确定未收录
            elif status == 200:
                html = resp.read().decode("utf-8", errors="replace")
                m = re.search(
                    r">组织名称</td>\s*<td[^>]*>\s*([^<]*?)\s*</td>",
                    html, re.S)
                if m:
                    vendor = re.sub(r"\s+", " ", m.group(1)).strip()
                cached = bool(vendor)  # 200 但解析不到组织名称 = 页面异常, 不缓存
    except Exception as e:
        # urllib 对 4xx 直接抛 HTTPError: 404 = 确定未收录, 缓存空串避免重复请求
        try:
            from urllib.error import HTTPError
            if isinstance(e, HTTPError) and e.code == 404:
                cached = True
        except Exception:
            cached = False
    if cached:
        with _OUI_ONLINE_LOCK:
            _OUI_ONLINE_CACHE[prefix] = vendor
    return vendor


class LANDeviceScanner:
    """局域网设备扫描 (ping sweep + ARP 表交叉 + MAC 厂商识别)。"""

    def __init__(self):
        self.name = "LAN 设备扫描"
        self.results = {}

    def _get_arp_map(self):
        """返回 {ip: mac} 字典。"""
        arp_map = {}
        code, out, _ = run_cmd("arp -a")
        for line in out.split("\n"):
            m = re.match(
                r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}",
                line)
            if m:
                parts = line.split()
                if len(parts) >= 2:
                    arp_map[parts[0]] = parts[1]
        return arp_map

    def detect(self, callback=None):
        if callback:
            callback("扫描局域网设备 (ARP 表)...")
        local_ip = get_local_ip()
        gateway = get_default_gateway()
        # 用真实子网掩码过滤 (而非硬编码 /24 — 大子网 /16 /23 会漏掉设备)
        local_net = _get_local_subnet(local_ip)
        devices = []

        # 以 ARP 表为主 (一次命令获取全部近期通信设备, 避免 254 次 ping sweep)
        arp_map = self._get_arp_map()
        for ip, mac in sorted(arp_map.items()):
            if local_net and ipaddress.IPv4Address(ip) not in local_net:
                continue
            # 过滤广播/组播/协议保留 MAC (用统一 helper, 比手写前缀更稳):
            #   - ff-ff-ff-ff-ff-ff  L2 广播
            #   - 01-00-5e-xx-xx-xx   IPv4 组播 (224/4)
            #   - 33-33-xx-xx-xx-xx   IPv6 组播 (ff02::/16)
            #   - 01-80-c2-00-00-0x   LLDP/MSTP/CDP 等链路层协议保留
            if not _is_valid_unicast_mac(mac):
                continue
            devices.append({
                "ip": ip, "mac": mac, "vendor": _oui_vendor(mac),
                "is_gateway": "是" if ip == gateway else "",
            })

        # 在线补查本地表未命中的厂商 (mac.bmcx.com): OUI 级去重 + 并发,
        # 失败/离线时静默保持"未知", 不影响扫描主流程。
        unknown_ouis = {}
        for d in devices:
            if not d.get("vendor") and d.get("mac"):
                p6 = d["mac"].replace("-", "").replace(":", "").upper()[:6]
                unknown_ouis.setdefault(p6, d["mac"])
        if unknown_ouis:
            hits = {}

            def _lookup(pair):
                p6, mac = pair
                return p6, _oui_vendor_online(mac)

            if len(unknown_ouis) == 1:
                p6, mac = next(iter(unknown_ouis.items()))
                hits[p6] = _oui_vendor_online(mac)
            else:
                with ThreadPoolExecutor(max_workers=4) as _ex:
                    _futs = [_ex.submit(_lookup, (p6, mac))
                             for p6, mac in unknown_ouis.items()]
                    for _f in as_completed(_futs):
                        try:
                            _p6, _v = _f.result()
                            if _v:
                                hits[_p6] = _v
                        except Exception:
                            pass
            for d in devices:
                if not d.get("vendor") and d.get("mac"):
                    p6 = d["mac"].replace("-", "").replace(":", "").upper()[:6]
                    if hits.get(p6):
                        d["vendor"] = hits[p6]

        # 评估
        issues = []
        if not devices:
            issues.append("未发现任何局域网设备 (扫描可能受防火墙/权限限制)")
            assessment = "扫描无结果"
        else:
            unknown = sum(1 for d in devices if not d["vendor"] and d["mac"])
            if gateway and not any(d["ip"] == gateway for d in devices):
                issues.append(f"网关 {gateway} 未出现在扫描结果中, 可能隔离或离线")
            assessment = f"发现 {len(devices)} 台设备"
            if unknown > 0:
                issues.append(f"{unknown} 台设备厂商未知 (可能是虚拟/物联网设备)")

        self.results = {
            "local_ip": local_ip,
            "gateway": gateway,
            "subnet": str(local_net) if local_net else "",
            "devices": devices,
            "device_count": len(devices),
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"LAN 扫描: 发现 {len(devices)} 台设备",
        }
        if callback:
            callback(self.results["summary"])
        return self.results


def _tcp_stats_snapshot():
    """采集系统 TCP 传输统计 (开机以来的累计计数器)。

    v1.7.0 (PR-F0): 从 TCPStatsTester.detect 提取为模块级函数 —
    diagnose 单次采样与盯障模式 (MonitorSession) 的周期采样共用。
    计数器是开机累计值, 会话口径由调用方做差分。
    返回 dict; 两条采集路径都失败时返回空 dict。
    """
    # 优先 PowerShell Get-NetTCPStatistics (结构化), 回退 netstat -s
    stats = {}
    code, out, _ = run_ps(
        "Get-NetTCPStatistics | Select-Object "
        "SegmentSent, SegmentReceived, RetransmittedSegments, "
        "Errors, FailureCounts, ConnectionsInitiated, "
        "ConnectionsAccepted, CurrentConnections | ConvertTo-Json")
    if out and out.strip():
        try:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]
            d = data[0] if data else {}
            stats = {
                "segments_sent": int(d.get("SegmentSent", 0) or 0),
                "segments_received": int(d.get("SegmentReceived", 0) or 0),
                "retransmitted": int(d.get("RetransmittedSegments", 0) or 0),
                "error_segments": int(d.get("Errors", 0) or 0),
                "conn_failures": int(d.get("FailureCounts", 0) or 0),
                "connections_initiated": int(d.get("ConnectionsInitiated", 0) or 0),
                "connections_accepted": int(d.get("ConnectionsAccepted", 0) or 0),
                "current_connections": int(d.get("CurrentConnections", 0) or 0),
            }
        except Exception:
            pass

    if not stats or stats.get("segments_sent", 0) == 0:
        # 回退: netstat -s 解析 (中英文)
        code, out, _ = run_cmd("netstat -s")
        if out:
            parsed = TCPStatsTester._parse_netstat_s(out)
            if parsed:
                # 用 netstat 结果补齐/覆盖
                for k, v in parsed.items():
                    if v:
                        stats[k] = v

    # 当前连接数修正: Get-NetTCPStatistics 在多数 Windows 上不存在该 cmdlet
    # (NetTCPIP 模块只提供 Get-NetTCPConnection), 之前 CurrentConnections 取不到时
    # 静默落为 0, 与「TCP 连接数检测」模块 (netstat -ano) 矛盾, 属"假零"。
    # 改为从 netstat -ano 计数 (与 TCPConnectionAnalyzer 口径一致);
    # 计数失败/为 0 时回退 Get-NetTCPStatistics 原值, 都没有则置 None (报告渲染为 —)。
    try:
        cc_orig = stats.get("current_connections")
        _code, _out, _ = run_cmd("netstat -ano", timeout=15)
        tcp_cnt = 0
        for _l in _out.split("\n"):
            _ls = _l.strip()
            if _ls.startswith("TCP") and len(_ls.split()) >= 5:
                tcp_cnt += 1
        stats["current_connections"] = (tcp_cnt if tcp_cnt > 0
                                        else (cc_orig if cc_orig else None))
    except Exception:
        stats["current_connections"] = stats.get("current_connections")

    return stats


def _default_route_if_mtu():
    """取默认路由出口接口的 MTU (v1.7.0 PR-F0)。

    盯障的 MTU 不匹配判据要拿「本机出口接口 MTU」与「路径 MTU」对比 —
    取默认路由接口 (Get-NetRoute 0.0.0.0/0 最优 metric) 而非全部已连接
    接口的极值, 避免 VPN/环回口污染。失败返回 (None, "")。
    """
    code, out, _ = run_ps(
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Sort-Object RouteMetric | Select-Object -First 1; "
        "if ($r) { Get-NetIPInterface -AddressFamily IPv4 "
        "-InterfaceIndex $r.InterfaceIndex | "
        "Select-Object InterfaceAlias, NlMtu | ConvertTo-Json }")
    if out and out.strip():
        try:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]
            if data:
                mtu = int(data[0].get("NlMtu", 0) or 0)
                return (mtu or None), data[0].get("InterfaceAlias", "") or ""
        except Exception:
            pass
    return None, ""


class TCPStatsTester:
    """TCP 传输质量统计 (重传率/错误段/失败连接), 基于 Get-NetTCPStatistics。"""

    def __init__(self):
        self.name = "TCP 传输质量"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("采集 TCP 传输统计...")
        stats = _tcp_stats_snapshot()

        sent = stats.get("segments_sent", 0)
        retrans = stats.get("retransmitted", 0)
        retrans_rate = round(retrans / sent * 100, 2) if sent else 0.0
        stats["retrans_rate_pct"] = retrans_rate

        # 评估
        issues = []
        if retrans_rate > 5:
            issues.append(
                f"TCP 重传率 {retrans_rate}% 偏高, 可能存在网络拥塞或链路质量问题")
            assessment = "TCP 传输质量异常"
        elif retrans_rate > 1:
            issues.append(f"TCP 重传率 {retrans_rate}% 略高, 建议关注")
            assessment = "TCP 传输质量一般"
        else:
            assessment = "TCP 传输质量正常"
        if stats.get("error_segments", 0) > 0:
            issues.append(f"TCP 错误段 {stats['error_segments']} 个")
        if stats.get("conn_failures", 0) > 0:
            issues.append(f"TCP 失败连接 {stats['conn_failures']} 次")

        self.results = {
            **stats,
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"TCP 重传率 {retrans_rate}% (重传 {retrans}/发送 {sent})",
        }
        if callback:
            callback(self.results["summary"])
        return self.results

    @staticmethod
    def _parse_netstat_s(out):
        """从 netstat -s 输出解析 TCP 统计 (中英文兼容)。"""
        stats = {k: 0 for k in
                 ("segments_sent", "segments_received", "retransmitted",
                  "error_segments", "conn_failures")}
        patterns = {
            "segments_sent": r"(Segments Sent|发送的分段)\D+(\d+)",
            "segments_received": r"(Segments Received|接收的分段)\D+(\d+)",
            "retransmitted": r"(Segments Retransmitted|重新传输的分段)\D+(\d+)",
            "error_segments": r"(Errors|错误的分段)\D+(\d+)",
            "conn_failures": r"(Connections Failed|Failures|失败)\D+(\d+)",
        }
        for key, pat in patterns.items():
            m = re.search(pat, out)
            if m:
                stats[key] = int(m.group(2))
        return stats if any(stats.values()) else {}



# ============================================================
# SECTION 4c: 新增诊断模块 (proxy / nattype / web / tcpcc)
# ============================================================

class ProxyDetector:
    """系统代理 / 加速器残留检测。

    四个来源全清点: WinINET 注册表 (浏览器/系统代理)、WinHTTP (系统服务层)、
    环境变量 (命令行程序)、VPN/TAP 虚拟网卡。对已启用的代理再做
    "可达性 + 转发能力" 探测 — "代理挂着但服务器没了" 是
    '能连 WiFi 但打不开网页' 的高频根因。
    """

    PROBE_HOST = "www.baidu.com"   # 经代理转发 / 直连对照的探测目标

    def __init__(self):
        self.name = "代理检测"
        self.results = {}

    # ── 来源 1: WinINET (HKCU Internet Settings, 浏览器/系统代理) ──
    def _read_wininet(self):
        out = {}
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            try:
                for reg_name, field in (("ProxyEnable", "proxy_enable"),
                                        ("ProxyServer", "proxy_server_raw"),
                                        ("ProxyOverride", "proxy_override"),
                                        ("AutoConfigURL", "auto_config_url")):
                    try:
                        out[field] = winreg.QueryValueEx(key, reg_name)[0]
                    except FileNotFoundError:
                        pass
            finally:
                key.Close()
        except Exception as e:
            out["read_error"] = str(e)
            return out
        # ProxyServer 两种格式都解析:
        #   "host:port" (全部协议同代理) / "http=a:80; https=b:443; socks=c:1080"
        raw = str(out.get("proxy_server_raw") or "")
        server, endpoint = {}, None
        if raw:
            if "=" in raw:
                for part in raw.split(";"):
                    k, _, v = part.partition("=")
                    k, v = k.strip().lower(), v.strip()
                    if k and v:
                        server[k] = v
            else:
                server = {"http": raw, "https": raw, "ftp": raw, "socks": raw}
            endpoint = server.get("http") or server.get("https") or raw
        out["proxy_server"] = server
        out["proxy_endpoint"] = endpoint
        return out

    # ── 来源 2: WinHTTP (系统服务层代理, netsh 查看) ──
    def _read_winhttp(self):
        out = {}
        code, raw, _ = run_cmd("netsh winhttp show proxy", timeout=10)
        out["raw"] = (raw or "").strip()
        text = out["raw"]
        if not text:
            out["summary"] = "无法读取"
        elif re.search(r"直接访问|Direct access", text):
            out["summary"] = "直接访问 (无代理)"
        else:
            m = re.search(r"代理服务器|Proxy Server\(s\)\s*[:：]\s*(.+)", text)
            out["summary"] = (f"代理: {m.group(1).strip()}" if m
                              else "已配置 (见原始输出)")
            b = re.search(r"绕过|Bypass[^\n]*[:：]\s*(.+)", text)
            if b:
                out["bypass"] = b.group(1).strip()
        return out

    # ── 来源 3: 环境变量 (只影响命令行程序, 不影响浏览器) ──
    def _read_env(self):
        found = {}
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                  "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            v = os.environ.get(k)
            if v:
                found[k] = v
        return found

    # ── 来源 4: VPN / TAP 虚拟网卡 (加速器/企业 VPN 常驻) ──
    def _read_vpn_adapters(self):
        vpns = []
        for a in get_network_adapters():
            if str(a.get("status", "")).lower() not in ("up", ""):
                continue
            name, desc = a.get("name", ""), a.get("description", "")
            if _is_vpn_interface(name) or _is_vpn_interface(desc):
                vpns.append({"name": name, "description": desc,
                             "status": a.get("status", "")})
        return vpns

    # ── 来源 5: hosts 文件劫持检测 ──
    # 知名域名出现在 hosts 里本身就是异常 (正常用户不需要手写);
    # 指向私网/回环 = 明确劫持或屏蔽 (广告/钓鱼/家长控制残留);
    # 指向公网 = 可疑覆盖, 需人工确认。
    KNOWN_DOMAINS = frozenset((
        "baidu.com", "www.baidu.com", "qq.com", "www.qq.com",
        "weixin.qq.com", "wx.qq.com", "mail.qq.com",
        "taobao.com", "www.taobao.com", "tmall.com", "alipay.com",
        "jd.com", "www.jd.com", "weibo.com", "www.weibo.com",
        "bilibili.com", "www.bilibili.com", "163.com", "www.163.com",
        "zhihu.com", "www.zhihu.com", "douyin.com", "www.douyin.com",
        "12306.cn", "www.12306.cn", "icloud.com", "www.icloud.com",
    ))

    def _read_hosts(self):
        out = {"total_entries": 0, "hijacked": [], "suspicious": []}
        path = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"),
                            r"System32\drivers\etc\hosts")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            out["error"] = f"读取失败: {e}"[:60]
            return out
        for line in lines:
            line = line.split("#", 1)[0].strip()      # 去注释
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, hosts = parts[0], [h.lower().rstrip(".") for h in parts[1:]]
            out["total_entries"] += 1
            for h in hosts:
                if h not in self.KNOWN_DOMAINS:
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                    bad = addr.is_private or addr.is_loopback
                except ValueError:
                    bad = True                # 不是合法 IP 的映射更可疑
                entry = {"domain": h, "ip": ip}
                (out["hijacked"] if bad else out["suspicious"]).append(entry)
        return out

    # ── 代理可用性探测: TCP 可达 + 经代理转发 + 直连对照 ──
    def _probe(self, endpoint):
        res = {"performed": True, "proxy_endpoint": endpoint}
        res["tcp_ms"] = _tcping_ms(endpoint, timeout=3.0)
        res["tcp_ok"] = res["tcp_ms"] is not None
        host, _, port = endpoint.rpartition(":")
        if not port.isdigit():
            host, port = endpoint, "80"
        # 经代理转发: HTTP 代理对绝对 URI 的 GET (200/3xx 均算通)
        try:
            t0 = time.perf_counter()
            conn = http.client.HTTPConnection(host, int(port), timeout=8)
            conn.request("GET", f"http://{self.PROBE_HOST}/",
                         headers={"User-Agent": "NetPulse/1.0",
                                  "Host": self.PROBE_HOST})
            resp = conn.getresponse()
            resp.read(4096)
            res["via_proxy_status"] = resp.status
            res["via_proxy_ms"] = round((time.perf_counter() - t0) * 1000)
            conn.close()
        except Exception as e:
            res["via_proxy_status"] = None
            res["via_proxy_error"] = str(e)[:80]
        res["via_proxy_ok"] = res.get("via_proxy_status") in (200, 301, 302, 303, 307, 308)
        # 直连对照
        try:
            t0 = time.perf_counter()
            conn = http.client.HTTPConnection(self.PROBE_HOST, 80, timeout=8)
            conn.request("GET", "/", headers={"User-Agent": "NetPulse/1.0"})
            resp = conn.getresponse()
            resp.read(4096)
            res["direct_status"] = resp.status
            res["direct_ms"] = round((time.perf_counter() - t0) * 1000)
            conn.close()
        except Exception as e:
            res["direct_status"] = None
            res["direct_error"] = str(e)[:80]
        res["direct_ok"] = res.get("direct_status") in (200, 301, 302, 303, 307, 308)
        return res

    def _probe_pac(self, url):
        try:
            with _urlopen_with_proxy(url, timeout=4) as resp:
                resp.read(1024)
            return True
        except Exception:
            return False

    def detect(self, callback=None):
        if callback:
            callback("读取系统代理配置...")
        wininet = self._read_wininet()
        winhttp = self._read_winhttp()
        env = self._read_env()
        if callback:
            callback("检查 VPN/虚拟网卡...")
        vpns = self._read_vpn_adapters()

        wininet_on = bool(wininet.get("proxy_enable")) and wininet.get("proxy_endpoint")
        env_ep = None
        for k in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
                  "HTTPS_PROXY", "https_proxy"):
            v = env.get(k)
            if v:
                env_ep = v.split("://", 1)[-1].rstrip("/")
                break
        endpoint = wininet.get("proxy_endpoint") if wininet_on else env_ep
        if callback:
            callback("检查 hosts 文件...")
        hosts_check = self._read_hosts()

        probe = None
        if endpoint:
            if callback:
                callback(f"探测代理可用性 {endpoint} ...")
            probe = self._probe(endpoint)
        pac_url = wininet.get("auto_config_url")
        pac_reachable = self._probe_pac(pac_url) if pac_url else None

        # 探测结论 (判定矩阵见 _verdict_proxy 的注释)
        if probe:
            if not probe["tcp_ok"]:
                verdict = "unreachable"      # 代理服务器都没了
            elif not probe["via_proxy_ok"] and probe["direct_ok"]:
                verdict = "no_forward"       # 代理在但不转发
            elif probe["via_proxy_ok"] and probe["direct_ok"]:
                verdict = "ok_both"          # 双通, 代理正常
            elif probe["via_proxy_ok"]:
                verdict = "only_proxy"       # 只能经代理上网
            else:
                verdict = "both_fail"        # 双败 = 上游链路问题, 非代理本身
        elif pac_url:
            verdict = "pac"
        else:
            verdict = "none"

        # issues (detect 侧存结构化记录, 客户视图文案在 _issues_proxy)
        issues = []
        if verdict == "unreachable":
            assessment = "代理不可用(异常)"
            issues.append({"type": "proxy_unreachable", "severity": "critical",
                           "message": f"系统代理已开启但代理服务器 {endpoint} 不可达",
                           "detail": "疑似断网根因: 浏览器/走系统代理的应用会全部断网"})
        elif verdict == "no_forward":
            assessment = "代理不可用(异常)"
            issues.append({"type": "proxy_no_forward", "severity": "critical",
                           "message": f"代理 {endpoint} 可达但拒绝转发请求",
                           "detail": "疑似断网根因: 代理进程异常或认证失效"})
        elif verdict == "only_proxy":
            assessment = "仅能经代理上网"
            issues.append({"type": "proxy_only_path", "severity": "warning",
                           "message": "仅能经代理上网 (直连失败)",
                           "detail": "关闭代理会断网, 排障时勿直接关代理"})
        elif verdict == "both_fail":
            assessment = "代理与直连均失败"
            issues.append({"type": "upstream_down", "severity": "warning",
                           "message": "经代理与直连均失败",
                           "detail": "上游链路问题, 非代理本身"})
        elif verdict in ("ok_both", "pac"):
            assessment = "代理可用" if verdict == "ok_both" else "PAC 自动配置模式"
        else:
            assessment = "无代理直连环境"
        if vpns:
            issues.append({"type": "vpn_adapter", "severity": "warning",
                           "message": f"检测到 {len(vpns)} 块 VPN/虚拟网卡 "
                                      f"({', '.join(v['name'] for v in vpns)})",
                           "detail": "流量可能经 VPN 隧道, 各模块测得的是隧道链路而非物理宽带"})
        if pac_url:
            reach = "可达" if pac_reachable else "不可达"
            issues.append({"type": "pac", "severity": "info",
                           "message": f"检测到 PAC 自动配置 ({pac_url}, {reach})",
                           "detail": "PAC 脚本决定分流, 注册表静态值不代表实际代理"})
        if env:
            issues.append({"type": "env_proxy", "severity": "info",
                           "message": "环境变量代理: " + ", ".join(f"{k}={v}" for k, v in env.items()),
                           "detail": "仅影响命令行程序 (curl/pip 等), 不影响浏览器"})
        for e in hosts_check.get("hijacked", []):
            issues.append({"type": "hosts_hijack", "severity": "critical",
                           "message": f"hosts 劫持: {e['domain']} → {e['ip']} (私网/回环地址)",
                           "detail": "浏览器访问该域名会被导向内网或黑洞 — "
                                     "'网页打不开/被导向错误页面'的直接根因"})
        for e in hosts_check.get("suspicious", []):
            issues.append({"type": "hosts_suspicious", "severity": "warning",
                           "message": f"hosts 可疑覆盖: {e['domain']} → {e['ip']}",
                           "detail": "正常使用不需要在 hosts 里写知名域名, 疑似软件/人为篡改"})
        total_hosts = hosts_check.get("total_entries", 0)
        if total_hosts > 30:
            issues.append({"type": "hosts_bulk", "severity": "info",
                           "message": f"hosts 文件有 {total_hosts} 条有效记录",
                           "detail": "被某些工具 (加速器/去广告/破解补丁) 大量写入, 建议检查来源"})

        if verdict == "none":
            summary = "未配置系统代理 (WinINET/WinHTTP/环境变量)"
        elif verdict == "ok_both":
            summary = (f"系统代理开启且可用 ({endpoint}: 经代理 "
                       f"{probe.get('via_proxy_status')} / 直连 {probe.get('direct_status')})")
        elif verdict == "pac":
            summary = f"PAC 自动配置模式 ({pac_url})"
        elif verdict == "unreachable":
            summary = f"系统代理开启但代理服务器 {endpoint} 不可达 — 疑似断网根因"
        elif verdict == "no_forward":
            summary = f"系统代理开启但无法转发请求 ({endpoint}) — 疑似断网根因"
        elif verdict == "only_proxy":
            summary = "仅能经代理上网 (直连失败), 关闭代理会断网"
        else:
            summary = "经代理与直连均失败 — 上游链路问题, 非代理本身"

        self.results = {
            "method": "winreg + netsh + 环境变量 + hosts + 转发探测",
            "wininet": wininet,
            "winhttp": winhttp,
            "env_proxies": env,
            "vpn_adapters": vpns,
            "hosts_check": hosts_check,
            "probe": probe,
            "pac_reachable": pac_reachable,
            "verdict": verdict,
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class NATTypeTester:
    """NAT 类型检测 (STUN Binding, RFC3489/5389 兼容, 纯标准库实现)。

    用同一个 UDP socket 先后向两台不同 STUN 服务器发 Binding Request,
    对比各自回报的映射地址 (ip, port):
      - 完全相同 → 锥形 (EIM, 对 P2P 友好)
      - 不同 → 对称型 (每个目标分配不同映射, P2P 打洞难)
    同时回答 "UDP 出网是否受阻" (全部服务器无响应) — 游戏联机/语音
    通话不通的两大根因一次判定。服务器支持 CHANGE-REQUEST (响应带
    CHANGED-ADDRESS) 时再细分全锥形/受限锥形, 否则明确标"未细分"不猜。
    """

    # 前两台 2026-08 实测可用 (qq/小米当时超时, 留作替补); 全部自动回退
    CANDIDATE_SERVERS = [
        ("stun.chat.bilibili.com", 3478),
        ("stun.hitv.com", 3478),
        ("stun.qq.com", 3478),
        ("stun.miwifi.com", 3478),
    ]
    TIMEOUT_S, RETRIES = 2.0, 2

    def __init__(self):
        self.name = "NAT 类型"
        self.results = {}

    @staticmethod
    def _binding_request():
        # 带 RFC5389 magic cookie: 新服务器按 5389 回 XOR-MAPPED-ADDRESS;
        # 老 RFC3489 服务器把 cookie+txid 当 16 字节 txid 原样回显, 两种都兼容
        return struct.pack(">HH", 0x0001, 0) + b"\x21\x12\xa4\x42" + os.urandom(12)

    @staticmethod
    def _parse_binding(resp, req):
        """解析 Binding Success Response → (mapped, changed); 非法返回 None。"""
        if len(resp) < 20 or resp[:2] != b"\x01\x01":
            return None
        if resp[4:20] != req[4:20]:        # txid 回显校验, 防串包
            return None
        mapped = changed = None
        off = 20
        while off + 4 <= len(resp):
            atype, alen = struct.unpack(">HH", resp[off:off + 4])
            val = resp[off + 4:off + 4 + alen]
            if atype in (0x0001, 0x0020) and alen >= 8 and val[1] == 0x01:
                port = struct.unpack(">H", val[2:4])[0]
                ipn = struct.unpack(">I", val[4:8])[0]
                if atype == 0x0020:        # XOR-MAPPED-ADDRESS: 异或还原
                    port ^= 0x2112
                    ipn ^= 0x2112A442
                mapped = (str(ipaddress.ip_address(ipn)), port)
            elif atype == 0x0005 and alen >= 8 and val[1] == 0x01:
                port = struct.unpack(">H", val[2:4])[0]
                ipn = struct.unpack(">I", val[4:8])[0]
                changed = (str(ipaddress.ip_address(ipn)), port)
            off += 4 + alen + ((4 - alen % 4) % 4)
        return mapped, changed

    def _query(self, sock, server):
        """向 server 发 Binding (最多 RETRIES 次) → (mapped, changed, rtt_ms, err)。"""
        for _ in range(self.RETRIES):
            req = self._binding_request()
            t0 = time.perf_counter()
            try:
                sock.sendto(req, server)
                resp, src = sock.recvfrom(2048)
                if src[0] != server[0]:
                    continue                # 响应来自别的 IP (负载均衡错配), 丢弃重试
                parsed = self._parse_binding(resp, req)
                if parsed and parsed[0]:
                    return parsed[0], parsed[1], round((time.perf_counter() - t0) * 1000), ""
            except socket.timeout:
                continue
            except OSError as e:
                return None, None, None, str(e)[:60]
        return None, None, None, "无响应"

    def _cone_refine(self, sock, server):
        """CHANGE-REQUEST (改 IP+改端口) 细分: 有响应 = 全锥形, 超时 = 受限锥形。"""
        req = (struct.pack(">HH", 0x0001, 4) + b"\x21\x12\xa4\x42" + os.urandom(12)
               + struct.pack(">HHI", 0x0003, 4, 0x0006))
        try:
            sock.sendto(req, server)
            resp, _src = sock.recvfrom(2048)
            if self._parse_binding(resp, req):
                return "全锥形"
        except Exception:
            pass
        return "受限锥形(未细分)"

    def detect(self, servers=None, callback=None):
        # 候选: 用户指定 (--nattype-server, 最多取两台) 或内置列表
        candidates = []
        for s in (servers or [])[:2]:
            host, _, port = s.rpartition(":")
            candidates.append((host, int(port)) if port.isdigit() else (s, 3478))
        if not candidates:
            candidates = list(self.CANDIDATE_SERVERS)

        records, alive = [], []            # alive: [(addr, mapped, changed)]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.TIMEOUT_S)
        try:
            # 并行取 TCP/HTTP 出口 IP, 与 STUN 互不等待
            pub_box = {}
            pub_t = threading.Thread(
                target=lambda: pub_box.update(ip=get_public_ip()),
                daemon=True)
            pub_t.start()

            for host, port in candidates:
                label = f"{host}:{port}"
                if len(alive) >= 2:
                    records.append({"server": label, "ok": None, "mapped_addr": "",
                                    "rtt_ms": None, "error": "未测 (已取到两台)",
                                    "changed_addr": ""})
                    continue
                try:
                    addr = socket.getaddrinfo(host, port, socket.AF_INET,
                                              socket.SOCK_DGRAM)[0][4]
                except Exception as e:
                    records.append({"server": label, "ok": False, "mapped_addr": "",
                                    "rtt_ms": None,
                                    "error": f"解析失败: {str(e)[:40]}",
                                    "changed_addr": ""})
                    continue
                if any(addr[0] == a[0][0] for a in alive):
                    records.append({"server": label, "ok": None, "mapped_addr": "",
                                    "rtt_ms": None, "error": "与已选服务器同 IP",
                                    "changed_addr": ""})
                    continue
                if callback:
                    callback(f"查询 STUN {label} ...")
                mapped, changed, rtt, err = self._query(s, addr)
                records.append({
                    "server": label, "ok": mapped is not None,
                    "mapped_addr": f"{mapped[0]}:{mapped[1]}" if mapped else "",
                    "rtt_ms": rtt, "error": err,
                    "changed_addr": f"{changed[0]}:{changed[1]}" if changed else ""})
                if mapped:
                    alive.append((addr, mapped, changed))

            udp_blocked = len(alive) == 0
            mapped_ip = mapped_port = None
            nat_behavior, cone_type = "未知(UDP受阻)", "—"
            if len(alive) >= 2:
                m1, m2 = alive[0][1], alive[1][1]
                mapped_ip, mapped_port = m1
                if m1 == m2:
                    nat_behavior = "EIM(锥形)"
                    # 只有响应里带 CHANGED-ADDRESS (支持 CHANGE-REQUEST) 才细分
                    cone_type = (self._cone_refine(s, alive[0][0])
                                 if (alive[0][2] or alive[1][2]) else "未细分")
                else:
                    nat_behavior = "对称型"
            elif len(alive) == 1:
                mapped_ip, mapped_port = alive[0][1]
                nat_behavior = "未知(单服务器)"
        finally:
            s.close()
        pub_t.join(6)
        public_ip = pub_box.get("ip")
        ip_match = None if (not mapped_ip or not public_ip) else (mapped_ip == public_ip)

        issues = []
        if udp_blocked:
            assessment = "UDP 出网异常"
            # 只测过 1 台时无法区分 "UDP 受阻" 和 "该服务器恰好不可用", 措辞留余地
            if len(candidates) == 1:
                msg = (f"指定的 STUN 服务器 ({candidates[0][0]}) 无响应 — "
                       "UDP 出网受阻或仅该服务器不可用")
            else:
                msg = (f"{len(candidates)} 台 STUN 服务器均无响应 — UDP 出网疑似受阻")
            issues.append({"type": "udp_blocked", "severity": "critical",
                           "message": msg,
                           "detail": "UDP 无法出网是游戏联机/语音通话不通的常见根因 (防火墙/路由器 UDP 过滤)"})
        elif nat_behavior == "对称型":
            assessment = "NAT 为对称型"
            issues.append({"type": "symmetric", "severity": "warning",
                           "message": "NAT 疑似对称型 — 不同目标分配不同映射 "
                                      f"({alive[0][1][0]}:{alive[0][1][1]} vs {alive[1][1][0]}:{alive[1][1][1]})",
                           "detail": "P2P 打洞成功率低, 游戏/语音直连难, 通常需中继 (RELAY)"})
        elif nat_behavior == "EIM(锥形)":
            assessment = "NAT 为锥形(EIM)"
            issues.append({"type": "eim", "severity": "info",
                           "message": "NAT 为锥形 (EIM) — 对 P2P 友好", "detail": ""})
        else:
            assessment = "无法判定 NAT 类型"
            issues.append({"type": "single_server", "severity": "info",
                           "message": "仅一台 STUN 服务器可达, 无法判定锥形/对称 (需两台不同服务器对比)",
                           "detail": ""})
        if ip_match is False:
            issues.append({"type": "egress_mismatch", "severity": "warning",
                           "message": f"UDP 映射 IP ({mapped_ip}) 与 HTTP 出口 ({public_ip}) 不一致",
                           "detail": "多出口链路或 UDP 走了代理/加速器"})

        if udp_blocked:
            summary = (f"指定的 STUN 服务器无响应 ({candidates[0][0]})"
                       if len(candidates) == 1
                       else f"UDP 出网受阻: {len(candidates)} 台 STUN 服务器均无响应")
        elif nat_behavior in ("EIM(锥形)", "对称型"):
            tail = f", UDP 出口 {mapped_ip} ≠ HTTP 出口 {public_ip}" if ip_match is False else ""
            summary = f"NAT 类型: {nat_behavior} — 映射 {mapped_ip}:{mapped_port}{tail}"
        elif nat_behavior == "未知(单服务器)":
            summary = f"无法判定锥形/对称 (仅一台服务器可达) — 映射 {mapped_ip}:{mapped_port}"
        else:
            summary = "NAT 类型检测未完成"

        self.results = {
            "method": "STUN Binding (RFC3489/5389 兼容)",
            "servers": records,
            "nat_behavior": nat_behavior,
            "cone_type": cone_type,
            "udp_blocked": udp_blocked,
            "mapped_ip": mapped_ip,
            "mapped_port": mapped_port,
            "mapped_addr": f"{mapped_ip}:{mapped_port}" if mapped_ip else "",
            "public_ip_tcp": public_ip,
            "ip_match": ip_match,
            "local_lan_ip": get_local_ip(),
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class WebPageTester:
    """网页体检: DNS → TCP → TLS → TTFB 分段计时 + 状态码/重定向/证书。

    把"ping 通但网页打不开"拆到具体层: DNS 解析失败 vs TCP 连不上 vs
    TLS 握手失败 (证书/中间盒) vs 首字节慢 (服务端/链路)。
    分段计时的三个关键实现细节:
      - 只用 http.client + 手动跟随重定向 (urlopen 会自动重定向并自动走
        系统代理, 污染分段计时);
      - 自己解析 IP 后把预连 socket 注入 conn.sock (跳过 HTTPConnection
        内部二次 getaddrinfo + IPv4/IPv6 双栈遍历);
      - GET + Range 限量读 + TCP_NODELAY (防 Nagle/delayed-ACK 干扰 TTFB)。
    """

    DEFAULT_TARGETS = ["https://www.qq.com", "https://www.baidu.com",
                       "https://www.aliyun.com"]
    MAX_TARGETS, MAX_REDIRECTS = 8, 5
    DNS_TIMEOUT, TCP_TIMEOUT, TLS_TIMEOUT, TTFB_TIMEOUT = 5, 5, 8, 10   # 秒
    BUDGET_S = 60            # 单目标总预算 (含全部重定向跳)

    def __init__(self):
        self.name = "网页体检"
        self.results = {}

    def _probe_hop(self, scheme, host, port, path):
        """单跳分段探测; 失败时结果含 fail_stage (dns/tcp/tls/http)。"""
        seg = {"dns_ms": None, "tcp_ms": None, "tls_ms": None, "ttfb_ms": None}
        # 1) DNS
        t0 = time.perf_counter()
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_INET,
                                       socket.SOCK_STREAM)
        except Exception as e:
            return {**seg, "fail_stage": "dns", "error": f"DNS 解析失败: {e}"[:80]}
        seg["dns_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        seg["resolved_ip"] = infos[0][4][0]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = None
        try:
            # 2) TCP
            sock.settimeout(self.TCP_TIMEOUT)
            t0 = time.perf_counter()
            sock.connect((seg["resolved_ip"], port))
            seg["tcp_ms"] = round((time.perf_counter() - t0) * 1000, 1)

            # 3) TLS (仅 https)
            if scheme == "https":
                t0 = time.perf_counter()
                try:
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                except ssl.SSLCertVerificationError:
                    seg["fail_stage"] = "tls"
                    seg["error"] = "证书校验失败 (过期/域名不符/中间人/系统时间错误)"
                    return seg
                except ssl.SSLError as e:
                    seg["fail_stage"] = "tls"
                    seg["error"] = f"TLS 握手失败: {e}"[:80]
                    return seg
                seg["tls_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                seg["tls_version"] = sock.version()
                cert = sock.getpeercert() or {}
                if cert.get("notAfter"):
                    try:
                        remain = ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()
                        seg["cert_days_left"] = round(remain / 86400, 1)
                        seg["cert_not_after"] = cert["notAfter"]
                        issuer = cert.get("issuer") or ()
                        if issuer:
                            # issuer 是形如 (('commonName', 'DigiCert ...'),) 的
                            # 嵌套元组, 逐层取最后一个元素直到得到字符串 (颁发者名)
                            node = issuer[-1]
                            for _ in range(4):
                                if isinstance(node, (tuple, list)) and node:
                                    node = node[-1]
                                else:
                                    break
                            seg["cert_issuer"] = str(node) if node else "N/A"
                    except Exception:
                        pass

            # 4) HTTP — 注入预连 socket, 跳过 conn.connect() 的二次解析
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            sock.settimeout(self.TTFB_TIMEOUT)   # socket 超时从 TCP 段的 5s 放宽到 TTFB 预算
            conn = http.client.HTTPConnection(host, port, timeout=self.TTFB_TIMEOUT)
            conn.sock = sock
            t0 = time.perf_counter()
            try:
                conn.request("GET", path or "/", headers={
                    "Host": host, "User-Agent": "NetPulse/1.0",
                    "Range": "bytes=0-65535", "Connection": "close"})
                resp = conn.getresponse()
                seg["ttfb_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                seg["status_code"] = resp.status
                seg["location"] = resp.getheader("Location")
                resp.read(65536)          # 限量读, 不下载整页
            except Exception as e:
                seg["fail_stage"] = "http"
                seg["error"] = f"HTTP 请求失败: {e}"[:80]
            return seg
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if not seg.get("fail_stage"):
                seg["fail_stage"] = "tcp"
                seg["error"] = f"TCP 连接失败: {e}"[:80]
            return seg
        finally:
            # conn.close() 连带关闭底层 socket; TLS 失败等提前 return 的路径补关
            try:
                if conn is not None:
                    conn.close()
                else:
                    sock.close()
            except Exception:
                pass

    def _probe_one(self, url):
        """完整探测一个 URL: 手动跟随重定向 (上限 MAX_REDIRECTS 跳)。
        分段耗时取首跳值 (用户输入的 URL 才是计时对象), 跳数单列。"""
        record = {"url": url, "final_url": url, "redirects": 0}
        chain = []
        current = url
        t_start = time.perf_counter()
        deadline = time.monotonic() + self.BUDGET_S
        for _hop in range(self.MAX_REDIRECTS + 1):
            if time.monotonic() > deadline:
                record["fail_stage"] = "http"
                record["error"] = "总耗时超预算 (60s)"
                break
            try:
                parts = urlsplit(current)
                scheme = (parts.scheme.lower() or "http")
                host = parts.hostname or ""
                port = parts.port or (443 if scheme == "https" else 80)
                path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            except ValueError as e:
                record["fail_stage"] = "dns"
                record["error"] = f"URL 无效: {e}"[:80]
                break
            if not host:
                record["fail_stage"] = "dns"
                record["error"] = "URL 缺少主机名"
                break
            seg = self._probe_hop(scheme, host, port, path)
            for k in ("dns_ms", "tcp_ms", "tls_ms", "ttfb_ms", "resolved_ip",
                      "tls_version", "cert_days_left", "cert_issuer",
                      "cert_not_after", "status_code"):
                if seg.get(k) is not None and record.get(k) is None:
                    record[k] = seg[k]
            if seg.get("fail_stage"):
                record["fail_stage"] = seg["fail_stage"]
                record["error"] = seg.get("error", "")
                break
            if seg.get("status_code") in (301, 302, 303, 307, 308) and seg.get("location"):
                nxt = urljoin(current, seg["location"])
                chain.append({"url": current, "next_url": nxt,
                              "status": seg["status_code"]})
                record["redirects"] += 1
                current = nxt
                continue
            record["final_url"] = current
            break
        else:
            record["fail_stage"] = "http"
            record["error"] = f"重定向超过 {self.MAX_REDIRECTS} 跳"
            record["final_url"] = current
        record["total_ms"] = round((time.perf_counter() - t_start) * 1000, 1)
        if chain:
            record["redirect_chain"] = chain
        return record

    def detect(self, extra_targets=None, callback=None):
        targets = list(self.DEFAULT_TARGETS)
        for u in (extra_targets or []):
            u = (u or "").strip()
            if u and u not in targets:
                targets.append(u)
        targets = targets[:self.MAX_TARGETS]
        if callback:
            callback(f"体检 {len(targets)} 个网页目标 (DNS/TCP/TLS/TTFB 分段)...")

        records, chains = [], []
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = {pool.submit(self._probe_one, u): u for u in targets}
            for fut in as_completed(futs):
                try:
                    rec = fut.result()
                except Exception as e:
                    rec = {"url": futs[fut], "redirects": 0,
                           "fail_stage": "http", "error": f"探测异常: {e}"[:80]}
                if rec.get("redirect_chain"):
                    chains.extend(rec.pop("redirect_chain"))
                records.append(rec)
        records.sort(key=lambda r: targets.index(r["url"]) if r.get("url") in targets else 99)

        ok_records = [r for r in records if not r.get("fail_stage")]
        ok_count = len(ok_records)

        def _avg(key):
            vals = [r[key] for r in ok_records if isinstance(r.get(key), (int, float))]
            return round(sum(vals) / len(vals), 1) if vals else None

        avg = {k: _avg(k) for k in ("dns_ms", "tcp_ms", "tls_ms", "ttfb_ms")}
        certs = [r["cert_days_left"] for r in records
                 if isinstance(r.get("cert_days_left"), (int, float))]
        min_cert = round(min(certs), 1) if certs else None
        fail_stages = {}
        for r in records:
            if r.get("fail_stage"):
                fail_stages[r["fail_stage"]] = fail_stages.get(r["fail_stage"], 0) + 1

        # 评级 + issues (断层定位: 每类失败给指向既有模块的 action)
        issues = []
        total = len(records)
        if total and ok_count == 0:
            assessment = "网页访问异常"
        elif ok_count < total:
            assessment = "网页访问一般"
        elif avg["ttfb_ms"] is not None and avg["ttfb_ms"] >= 500:
            assessment = "网页访问偏慢"
        else:
            assessment = "网页访问正常"
        for r in records:
            url, stage = r.get("url", ""), r.get("fail_stage")
            err = r.get("error", "")
            if stage == "dns":
                issues.append({"type": "dns_fail", "severity":
                               "critical" if ok_count == 0 else "warning",
                               "message": f"DNS 解析失败 ({url}): {err}", "detail": ""})
            elif stage == "tcp":
                issues.append({"type": "tcp_fail", "severity": "warning",
                               "message": f"TCP 连接失败 ({url}): {err}", "detail": ""})
            elif stage == "tls":
                is_cert = "证书校验失败" in err
                issues.append({"type": "tls_cert_fail" if is_cert else "tls_fail",
                               "severity": "critical" if is_cert else "warning",
                               "message": f"{'TLS 证书校验失败' if is_cert else 'TLS 握手失败'} ({url}): {err}",
                               "detail": ""})
            elif stage == "http":
                issues.append({"type": "http_fail", "severity": "warning",
                               "message": f"HTTP 请求失败 ({url}): {err}", "detail": ""})
            elif isinstance(r.get("ttfb_ms"), (int, float)) and r["ttfb_ms"] >= 2000:
                issues.append({"type": "ttfb_slow", "severity": "warning",
                               "message": f"首字节慢 ({url}: {r['ttfb_ms']:.0f}ms)",
                               "detail": "DNS/TCP/TLS 均正常时多为服务端或链路慢"})
            if isinstance(r.get("cert_days_left"), (int, float)):
                d = r["cert_days_left"]
                if d < 7:
                    issues.append({"type": "cert_expire", "severity": "critical",
                                   "message": f"证书已过期或即将过期 ({url}, 剩 {d} 天)",
                                   "detail": ""})
                elif d < 30:
                    issues.append({"type": "cert_soon", "severity": "warning",
                                   "message": f"证书即将到期 ({url}, 剩 {d} 天)", "detail": ""})

        slow = f", 平均首字节 {avg['ttfb_ms']:.0f}ms" if avg["ttfb_ms"] is not None else ""
        self.results = {
            "method": "http.client + ssl 分段计时",
            "targets": records,
            "redirect_chain": chains,
            "ok_count": ok_count,
            "total_count": total,
            "avg_dns_ms": avg["dns_ms"],
            "avg_tcp_ms": avg["tcp_ms"],
            "avg_tls_ms": avg["tls_ms"],
            "avg_ttfb_ms": avg["ttfb_ms"],
            "min_cert_days": min_cert,
            "fail_stages": fail_stages,
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"网页体检: {ok_count}/{total} 正常{slow}",
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class TCPConcurrencyTester:
    """TCP 并发连接能力阶梯测试: 回答"这条网络路径能同时撑多少条 TCP 连接"。

    装维场景: 廉价光猫/路由器 NAT 会话表小 (典型 1024~8192), 设备一连多
    就掉线/游戏掉线。本模块向目标 (默认公网 anycast DNS 的 TCP 53, 实测
    扛 1000+ 并发无压力) 阶梯建立**累计保持**的并发连接, 找成功率崩塌点
    = NAT 并发上限; 同时跑本机回环对照, 区分"本机瓶颈 (安全软件/系统
    限制) vs 网络路径瓶颈 (NAT/网关/运营商)"。

    实现要点 (Windows 高并发实测结论):
      - select() 后端 >512 fd 报错, 必须用 asyncio Proactor (IOCP);
      - asyncio.run 跑在 _run_module_with_timeout 的 daemon 线程里 (合法,
        每次调用全新事件循环, 不跨循环持有对象);
      - 连接跨级别保持打开 (NAT 表压满状态), 结束统一 SO_LINGER(1,0)
        RST 关闭, 避免数千 TIME_WAIT 占临时端口。
    """

    CANDIDATE_TARGETS = [("223.5.5.5", 53),     # AliDNS (anycast)
                         ("119.29.29.29", 53),   # DNSPod
                         ("114.114.114.114", 53)]
    LADDER_BASE = (50, 100, 200, 400, 800, 1600, 3200, 6400, 8000)
    HARD_MAX = 8000            # 防滥用硬上限 (Windows 临时端口 ~16k)
    SUCCESS_STOP = 0.90        # 单级成功率低于此值 → 自适应停止
    CONNECT_TIMEOUT_S = 5.0
    HOLD_S = 1.0               # 每级保持时长 (秒), 兼作级别间休整

    def __init__(self):
        self.name = "TCP 并发"
        self.results = {}
        self._family = socket.AF_INET

    # ── 目标选择: 自定义优先, 否则候选逐个预检 (20 并发小波次 ≥90% 即选中) ──
    # 预检必须测"并发友好度"而非单纯可达: 部分公网端点 (如实测中的 DNSPod)
    # 对单 IP 快速并发连接限流, 若只做串行预检会把目标限流误诊成用户 NAT 差。
    def _pick_target(self, custom, callback=None):
        if custom:
            host, _, port = custom.rpartition(":")
            if not port.isdigit():
                return None, custom, [{"host": custom, "port": None,
                                       "ok": 0, "fail": 0,
                                       "error": "目标需含端口, 例 223.5.5.5:53"}]
            host = host.strip("[]")
            try:
                info = socket.getaddrinfo(host, int(port), 0, socket.SOCK_STREAM)[0]
                self._family = info[0]
            except Exception as e:
                return None, custom, [{"host": host, "port": int(port),
                                       "ok": 0, "fail": 3, "error": f"解析失败: {e}"[:60]}]
            ok = sum(1 for _ in range(3)
                     if _tcping_ms(f"{host}:{port}", timeout=2.0) is not None)
            recs = [{"host": host, "port": int(port), "ok": ok, "fail": 3 - ok}]
            return ((host, int(port)) if ok >= 2 else None), f"{host}:{port}", recs

        records = []
        for host, port in self.CANDIDATE_TARGETS:
            if callback:
                callback(f"预检目标 {host}:{port} (20 并发) ...")
            rec = self._concurrency_precheck((host, port))
            records.append(rec)
            if rec.get("success_rate", 0) >= 90:
                return (host, port), f"{host}:{port}", records
        return None, "", records

    def _concurrency_precheck(self, addr, n=20):
        """候选端点并发友好度预检: n 条并发连接, 成功率 ≥90% 才算可用。"""
        held, stats = [], {"ok": 0, "timeout": 0, "refused": 0, "other": 0, "lat": []}
        try:
            asyncio.run(self._client_wave(addr, n, held, stats))
            rate = round(stats["ok"] / n * 100, 1)
            return {"host": addr[0], "port": addr[1], "ok": stats["ok"],
                    "fail": n - stats["ok"], "success_rate": rate}
        except Exception as e:
            return {"host": addr[0], "port": addr[1], "ok": 0, "fail": n,
                    "error": str(e)[:60]}
        finally:
            for s in held:
                self._rst_close(s)

    @staticmethod
    def _established_count():
        """当前 ESTABLISHED 连接数 (背景信息: 本机已有连接也在占 NAT 表)。"""
        try:
            _c, out, _e = run_cmd("netstat -ano -p tcp", timeout=15, use_cache=False)
            return sum(1 for l in (out or "").split("\n") if "ESTABLISHED" in l)
        except Exception:
            return None

    def _ladder(self, mx):
        return sorted({l for l in self.LADDER_BASE if l <= mx} | {mx})

    @staticmethod
    def _rst_close(sock):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    async def _run_ladder(self, addr, mx, callback):
        """阶梯主测: 每级补足到目标并发数 → 保持 → 下一级; 失败率超标即停。"""
        held, level_records = [], []
        try:
            levels = self._ladder(mx)
            for li, level in enumerate(levels):
                need = level - len(held)
                stats = {"ok": 0, "timeout": 0, "refused": 0, "other": 0, "lat": []}
                t0 = time.perf_counter()
                if need > 0:
                    await asyncio.gather(*[self._connect_one(addr, held, stats)
                                           for _ in range(need)])
                wave_s = max(time.perf_counter() - t0, 1e-6)
                lat = sorted(stats["lat"])
                rate = stats["ok"] / need if need else 1.0
                level_records.append({
                    "level": level, "attempted": need, "ok": stats["ok"],
                    "fail": need - stats["ok"] if need else 0,
                    "success_rate": round(rate * 100, 1),
                    "p50_ms": round(lat[len(lat) // 2], 1) if lat else None,
                    "p95_ms": round(lat[max(int(len(lat) * 0.95), len(lat) - 1)], 1) if lat else None,
                    "cps": round(stats["ok"] / wave_s, 1),
                    "fail_timeout": stats["timeout"], "fail_refused": stats["refused"],
                    "fail_other": stats["other"],
                    "wall_ms": round(wave_s * 1000),
                })
                rec = level_records[-1]
                if callback:
                    callback(f"并发 {level}: 成功率 {rec['success_rate']}%, "
                             f"保持 {len(held)} 条, p50 {rec['p50_ms'] or '—'}ms, "
                             f"{rec['cps']}/s")
                if need and rate < self.SUCCESS_STOP:
                    break
                if li < len(levels) - 1:
                    await asyncio.sleep(self.HOLD_S)
        finally:
            for s in held:                      # RST 关闭, 不留 TIME_WAIT
                self._rst_close(s)
            await asyncio.sleep(0.05)           # 让取消/关闭的 IOCP 操作落地
        return level_records

    @staticmethod
    async def _client_wave(addr, n, held, stats):
        await asyncio.gather(*[TCPConcurrencyTester._connect_one_static(addr, held, stats)
                               for _ in range(n)])

    async def _connect_one(self, addr, held, stats):
        await self._connect_one_static(addr, held, stats, self._family)

    @staticmethod
    async def _connect_one_static(addr, held, stats, family=socket.AF_INET):
        """单条非阻塞连接; 成功的 socket 进 held 保持打开, 失败分类计数。"""
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        t0 = time.perf_counter()
        try:
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, addr),
                                   TCPConcurrencyTester.CONNECT_TIMEOUT_S)
        except asyncio.TimeoutError:            # NAT 表满的典型症状
            stats["timeout"] += 1
            sock.close()
            return False
        except ConnectionRefusedError:          # 目标拒绝 (限流/安全软件)
            stats["refused"] += 1
            sock.close()
            return False
        except OSError:
            stats["other"] += 1
            sock.close()
            return False
        stats["ok"] += 1
        stats["lat"].append((time.perf_counter() - t0) * 1000)
        held.append(sock)
        return True

    def _loopback_baseline(self, level):
        """本机回环对照: 在公网失败级别 (或最大级别) 复测, 排除/坐实本机瓶颈。

        服务端用普通线程 accept 循环持有连接 (不用 asyncio.start_server —
        大量挂起 accept 下 server.close() 会触发 proactor 断言噪声);
        客户端仍走 asyncio (高并发连接必须 Proactor)。"""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(min(level + 64, 65535))
        port = srv.getsockname()[1]
        accepted, stop = [], threading.Event()

        def _accept_loop():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    accepted.append(srv.accept()[0])   # 只持有, 不读不关
                except socket.timeout:
                    continue
                except OSError:
                    return

        acc_t = threading.Thread(target=_accept_loop, daemon=True)
        acc_t.start()
        held, stats = [], {"ok": 0, "timeout": 0, "refused": 0, "other": 0, "lat": []}
        try:
            asyncio.run(self._client_wave(("127.0.0.1", port), level, held, stats))
            lat = sorted(stats["lat"])
            return {
                "level": level, "attempted": level, "ok": stats["ok"],
                "fail": level - stats["ok"],
                "success_rate": round(stats["ok"] / level * 100, 1) if level else 0.0,
                "p50_ms": round(lat[len(lat) // 2], 1) if lat else None,
                "p95_ms": round(lat[max(int(len(lat) * 0.95), len(lat) - 1)], 1) if lat else None,
            }
        finally:
            stop.set()
            acc_t.join(1.5)
            for s in accepted:
                self._rst_close(s)
            srv.close()
            for s in held:
                self._rst_close(s)
            time.sleep(0.05)

    def detect(self, max_concurrency=1600, target=None, callback=None):
        mx = max(50, min(self.HARD_MAX, int(max_concurrency or 1600)))
        addr, target_label, precheck = self._pick_target(target, callback)
        if not addr:
            self.results = {
                "error": ("无可用并发测试目标 — 候选公网端点均不可达; "
                          "可用 --tcpcc-target host:port 指定自建服务器"),
                "method": "asyncio-tcp 阶梯并发",
                "target_candidates": precheck,
                "timestamp": datetime.now().isoformat(),
            }
            return self.results

        established_before = self._established_count()
        if callback:
            callback(f"目标 {target_label}, 阶梯 50→{mx} (累计保持) ...")
        try:
            level_records = asyncio.run(self._run_ladder(addr, mx, callback))
        except Exception as e:
            self.results = {"error": f"并发测试异常: {e}", "method": "asyncio-tcp 阶梯并发",
                            "target": target_label, "timestamp": datetime.now().isoformat()}
            return self.results
        established_after = self._established_count()

        failed_level = next((r for r in level_records
                             if r["attempted"] and r["success_rate"] < self.SUCCESS_STOP * 100),
                            None)
        passed = [r for r in level_records
                  if r["attempted"] and r["success_rate"] >= self.SUCCESS_STOP * 100]
        max_sustained = passed[-1]["level"] if passed else 0
        capped = failed_level is None
        peak_cps = max((r["cps"] or 0) for r in level_records) if level_records else 0

        # 本机回环对照: 失败级别 (全通过则最大级别), 双方都跑不通才是本机问题
        base_level = failed_level["level"] if failed_level else (level_records[-1]["level"] if level_records else 0)
        baseline = None
        if base_level >= 50:
            if callback:
                callback(f"本机回环对照 {base_level} 并发 ...")
            try:
                baseline = self._loopback_baseline(base_level)
            except Exception:
                baseline = None

        if failed_level is None:
            bottleneck = "—"
        elif baseline is None:
            bottleneck = "未知"
        elif baseline.get("success_rate", 0) < self.SUCCESS_STOP * 100:
            bottleneck = "本机"
        else:
            bottleneck = "网络/NAT"

        shown = f"≥{max_sustained}" if capped and max_sustained else str(max_sustained)
        issues = []
        # capped = 全级别通过 (没找到失败点): 容量"至少 N", 不能因 N 小就判差
        if capped:
            assessment = f"TCP 并发能力达标 (≥{max_sustained}, 达设定上限)"
        elif max_sustained == 0:
            assessment = "TCP 并发能力差(首个级别即失败)"
        elif max_sustained < 512:
            assessment = "TCP 并发能力差"
        elif max_sustained < 1024:
            assessment = "TCP 并发能力偏低"
        elif max_sustained < 2048:
            assessment = "TCP 并发能力中等"
        else:
            assessment = "TCP 并发能力良好"
        if not capped and max_sustained < 512:
            issues.append({"type": "low_concurrency", "severity": "critical",
                           "message": f"TCP 并发能力差 (仅 {shown})",
                           "detail": "NAT 表/中间盒并发会话限制或本机安全软件拦截, "
                                     "多资源网页/多线程下载/P2P 会明显受限"})
        elif not capped and max_sustained < 1024:
            issues.append({"type": "low_concurrency", "severity": "warning",
                           "message": f"TCP 并发能力偏低 ({shown})",
                           "detail": "廉价光猫/路由器典型 NAT 表容量, 多设备家庭可能不够用"})
        if failed_level:
            ft, fr = failed_level["fail_timeout"], failed_level["fail_refused"]
            if ft and ft >= (failed_level["fail"] or 1) * 0.5:
                issues.append({"type": "fail_mode", "severity": "info",
                               "message": f"失败以超时为主 ({ft}/{failed_level['fail']}) — "
                                          "典型为 NAT/防火墙并发会话表满",
                               "detail": ""})
            elif fr and fr >= (failed_level["fail"] or 1) * 0.5:
                issues.append({"type": "fail_mode", "severity": "info",
                               "message": f"失败以拒绝对主 ({fr}/{failed_level['fail']}) — "
                                          "目标服务器限流或本机安全软件拦截",
                               "detail": "可换 --tcpcc-target 自建服务器复测排除目标侧因素"})
        # 高并发 P95 异常: 即使并发级别通过, 延迟 P95 > 500ms 也说明高并发吃力
        # (典型: 800/1600 级 P95 经常 2000-4000ms, 用户打开多网页会感觉卡)
        for lv in level_records:
            if (lv.get("success_rate", 0) >= 90
                    and isinstance(lv.get("p95_ms"), (int, float))
                    and lv["p95_ms"] > 500):
                issues.append({
                    "type": "high_p95",
                    "severity": "warning",
                    "message": (f"高并发时新建连接明显变慢 "
                 f"(并发 {lv['level']} 时, 95% 的连接需 {lv['p95_ms']:.0f}ms 才建立, "
                 f"参考值 500ms 内)"),
                    "detail": (f"虽然 {lv['level']} 并发能全部建立, 但 95% 的连接需要 {lv['p95_ms']:.0f}ms 才能完成, "
                               f"浏览器多 tab / 多线程下载 / P2P 会感觉卡顿, 通常是 NAT 表小或中间盒转发慢导致"),
                })
                break  # 只报最高级那条
        if bottleneck == "本机":
            issues.append({"type": "local_bottleneck", "severity": "warning",
                           "message": f"本机回环对照在 {base_level} 并发同样受限 — "
                                      "疑似本机瓶颈 (安全软件/系统限制), 而非网络/NAT",
                           "detail": ""})
        elif bottleneck == "网络/NAT":
            issues.append({"type": "path_bottleneck", "severity": "info",
                           "message": f"本机回环 {base_level} 并发通过, 瓶颈在网络路径 "
                                      "(NAT/网关/运营商)",
                           "detail": "检查路由器/光猫 NAT 并发会话数规格, 减少长连接设备"
                                     "(IoT/P2P), 必要时重启网关"})

        self.results = {
            "method": "asyncio-tcp 阶梯并发",
            "target": target_label,
            "target_candidates": precheck,
            "max_concurrency": mx,
            "levels": level_records,
            "max_sustained": max_sustained,
            "capped": capped,
            "peak_cps": peak_cps,
            "local_baseline": baseline,
            "local_baseline_level": base_level if baseline else None,
            "bottleneck": bottleneck,
            "established_before": established_before,
            "established_after": established_after,
            "note": "杀毒软件/企业终端管控可能压低并发上限; 高上限 (≥3200) 勿短时间重复运行",
            "issues": issues,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": (f"TCP 并发: 最大可持续 {shown}, 峰值建连 {peak_cps:.0f}/s"
                        + (f", 瓶颈 {bottleneck}" if bottleneck != "—" else "")
                        + f" (目标 {target_label})"),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


# ============================================================
# SECTION 4e: 盯障模式 (长时间监测, 找偶发掉线)
# ============================================================
# 独立顶层运行模式 (不进 MODULE_REGISTRY, 不受模块超时/`all` 影响):
#   python netpulse.py --monitor [SEC] [--monitor-target HOST]
# 4 路采集: 网关 ping / 外网 ping (各 1s, LatencyMonitor) + 外网 TCP 53 +
# DNS 解析 (各 5s, probe 线程)。落盘前做事件检测 (掉线/DNS 故障/延迟突增)
# 与分段定位 (内网侧 / 运营商侧 / 解析侧), 输出 CSV+HTML+JSON 三件套。

import atexit
import csv as _csv


def _monitor_pct(vals, q):
    """手写分位数 (排序取下标), 不引依赖。"""
    if not vals:
        return None
    vals = sorted(vals)
    return vals[max(0, min(round(q * (len(vals) - 1)), len(vals) - 1))]


def _merge_runs(stream, min_len, session_end, kind="loss"):
    """在归并流 [(kind, t, ...) | ("ok", t, ...)] 里找连续 kind 段。

    返回 [{start, n, end, open}] — end 为段后首个成功样本时刻 (即恢复时刻),
    段到会话结束仍未恢复时 end=session_end 且 open=True。"""
    runs, i = [], 0
    while i < len(stream):
        if stream[i][0] != kind:
            i += 1
            continue
        j = i
        while j < len(stream) and stream[j][0] == kind:
            j += 1
        if j - i >= min_len:
            runs.append({"start": stream[i][1], "n": j - i,
                         "end": stream[j][1] if j < len(stream) else session_end,
                         "open": j >= len(stream)})
        i = j
    return runs


def _strip_gaps(stream, gap_s):
    """把相邻间隔 > gap_s 的区间按『未知』剔除 (ping 卡死/系统睡眠),
    返回 (剔除后的流, gap 区间列表)。gap 两侧的丢包段不跨 gap 合并。"""
    gaps = []
    for a, b in zip(stream, stream[1:]):
        if b[1] - a[1] > gap_s:
            gaps.append((a[1], b[1]))
    if not gaps:
        return stream, []
    kept = [s for s in stream if not any(g0 < s[1] < g1 for g0, g1 in gaps)]
    return kept, gaps


def _detect_jitter_segments(loss_times, all_times, window_s, step_s,
                            min_loss, min_pct, min_samples=10):
    """真滑动窗口扫描『窗口内丢包集中』段 (v1.5.2 盯障增强, v1.5.3 修判据)。

    偶发掉线的典型形态不是连续中断, 而是短窗口内反复丢包 — 纯『连续丢包段』
    检测 (MIN_LOSS_BURST) 会漏掉。窗口起点只锚定在丢包时刻: 任意包含 ≥min_loss
    次丢包的窗口都可平移到窗口内最早丢包处而不丢样本, 因此无需按固定网格
    步进扫描, 也不依赖丢包束与会话起点的相位对齐 (v1.5.2 的固定 10s 网格会让
    跨度 50-60s 的丢包束落进网格缝隙整体漏检)。窗口计数用 bisect 二分
    (输入已时间有序), 不再逐窗全量线性扫描 — 24h 盯障汇总从分钟级降到毫秒级。
    触发: 窗口内丢包 ≥ min_loss, 或 (丢包 ≥2 次且样本 ≥ min_samples 个且
    丢包率 ≥ min_pct)。丢包率判据要求"反复丢包"且分母够大: 单次丢包不算抖动,
    样本不足 min_samples 的稀疏窗口只按绝对次数判 (v1.5.2 的『样本 ≥ 窗口
    一半』要求与丢包率 ≥ min_pct 在数学上互斥, 丢包率分支从未生效过)。
    相邻触发窗口 (间隔 ≤ step_s) 合并成段, 段界取段内最早/最晚丢包时刻,
    使事件时长贴合实际抖动期。
    返回 [{start, end, n_loss, n_total, loss_pct}] (绝对时间戳, 按 start 排序)。
    """
    if len(loss_times) < 2 or not all_times:
        return []
    losses = sorted(loss_times)
    samples = sorted(all_times)
    hits = []
    for i, t0 in enumerate(losses):
        t1 = t0 + window_s
        n_loss = bisect_left(losses, t1) - i
        n_total = bisect_left(samples, t1) - bisect_left(samples, t0)
        if (n_loss >= min_loss
                or (n_loss >= 2 and n_total >= min_samples
                    and n_loss / n_total * 100 >= min_pct)):
            hits.append((t0, t1))
    if not hits:
        return []
    # 相邻/重叠触发窗口合并 (间隔 ≤ step_s 视为连续抖动)
    windows = []
    cur_start, cur_end = hits[0]
    for w0, w1 in hits[1:]:
        if w0 <= cur_end + step_s:
            cur_end = max(cur_end, w1)
        else:
            windows.append((cur_start, cur_end))
            cur_start, cur_end = w0, w1
    windows.append((cur_start, cur_end))
    out = []
    for s0, s1 in windows:
        ls = [t for t in loss_times if s0 <= t <= s1]
        if not ls:
            continue
        # 段界与统计取段内最早/最晚丢包时刻, 贴合实际抖动期
        ns = [t for t in all_times if ls[0] <= t <= ls[-1]]
        out.append({"start": ls[0], "end": ls[-1],
                    "n_loss": len(ls), "n_total": len(ns),
                    "loss_pct": round(len(ls) / len(ns) * 100, 1) if ns else 0.0})
    return out


def _detect_monitor_events(snap, t0, ended_at):
    """事件检测 (纯后处理): 输入采集快照, 输出事件列表 (按时间排序)。

    事件定位口径:
      - 网关中断 = internal (本机↔网关段, 内网侧问题)
      - 外网中断与网关中断时间窗相交 = both_down; 窗口内网关正常 = carrier
        (运营商/上联侧); 网关数据不足 = unknown
      - DNS 连续失败且外网 ping 正常 = dns (独立解析故障); 否则随外网中断
      - TCP 连续失败且 ping 正常 = policy (疑似端口策略/QoS, 信息级)
      - 延迟突增: 前 30 个成功样本 p50 为基线, 10s 桶 p95 > max(3×基线, 200ms)
    """
    events = []
    gw, gw_gaps = _strip_gaps(snap["gw_stream"], MonitorSession.GAP_S)
    ext, ext_gaps = _strip_gaps(snap["ext_stream"], MonitorSession.GAP_S)

    def _add(type_, stream, start, end, open_at_end, cls="", detail="", **extra):
        ev = {"type": type_, "stream": stream, "cls": cls,
              "start_ts": start, "end_ts": end,
              "duration_s": round(end - start, 1),
              "open_at_end": open_at_end, "detail": detail}
        ev.update(extra)
        events.append(ev)

    for g0, g1 in sorted(set(gw_gaps + ext_gaps)):
        _add("monitor_gap", "", g0, g1, False,
             detail="采集间隙 (ping 无输出 — 系统睡眠/进程阻塞?), 该区间按未知处理")

    def _disp(ts):
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")

    # 全程无回复特判 (优先于 run 拆分)
    ext_no_reply = (len(ext) >= 5 and not any(s[0] == "ok" for s in ext))
    gw_no_reply = (len(gw) >= 5 and not any(s[0] == "ok" for s in gw))
    if gw_no_reply:
        _add("outage", "gw", t0, ended_at, True, "internal",
             f"网关全程无回复 (共 {len(gw)} 行)")
    if ext_no_reply:
        tcp_ok = any(s[1] is not None for s in snap["tcp"])
        dns_ok = any(s[1] is not None for s in snap["dns"])
        cls = "target_unreachable" if (tcp_ok or dns_ok) else "no_data"
        _add("outage", "ext", t0, ended_at, True, cls,
             f"外网目标全程无 ICMP 回复 (共 {len(ext)} 行)")

    # 中断事件 (网关 / 外网)
    gw_runs = ([] if gw_no_reply
               else _merge_runs(gw, MonitorSession.MIN_LOSS_BURST, ended_at))
    ext_runs = ([] if ext_no_reply
                else _merge_runs(ext, MonitorSession.MIN_LOSS_BURST, ended_at))
    for r in gw_runs:
        _add("outage", "gw", r["start"], r["end"], r["open"], "internal",
             f"连续丢包 {r['n']} 次 (本机到网关段)")
    for r in ext_runs:
        win0, win1 = r["start"] - 2, r["end"] + 2
        overlapped = any(gr["start"] - 2 <= win1 and gr["end"] + 2 >= win0
                         for gr in gw_runs)
        if overlapped:
            cls, detail = "both_down", f"连续丢包 {r['n']} 次 (与网关中断同时发生)"
        else:
            gw_ok = sum(1 for s in gw if s[0] == "ok" and win0 <= s[1] <= win1)
            if gw_ok >= 3:
                cls = "carrier"
                detail = f"连续丢包 {r['n']} 次, 期间网关 ping 正常 — 运营商/上联侧"
            else:
                cls = "unknown"
                detail = f"连续丢包 {r['n']} 次, 窗口内网关数据不足, 无法定位"
        _add("outage", "ext", r["start"], r["end"], r["open"], cls, detail)

    # DNS 事件
    dns_stream = [("ok" if s[1] is not None else "fail", s[0], s[1])
                  for s in snap["dns"]]
    for r in _merge_runs(dns_stream, MonitorSession.MIN_DNS_FAIL, ended_at,
                         kind="fail"):
        win0, win1 = r["start"] - 2, r["end"] + 2
        ext_ok = sum(1 for s in ext if s[0] == "ok" and win0 <= s[1] <= win1)
        cls = "dns" if ext_ok else "with_outage"
        detail = (f"连续失败 {r['n']} 次" +
                  (", 期间外网 ping 正常 — 解析侧问题" if ext_ok
                   else ", 随外网中断发生"))
        _add("dns_fail", "dns", r["start"], r["end"], r["open"], cls, detail)

    # TCP 事件 (信息级)
    tcp_stream = [("ok" if s[1] is not None else "fail", s[0], s[1])
                  for s in snap["tcp"]]
    for r in _merge_runs(tcp_stream, 2, ended_at, kind="fail"):
        win0, win1 = r["start"] - 2, r["end"] + 2
        ext_ok = sum(1 for s in ext if s[0] == "ok" and win0 <= s[1] <= win1)
        _add("tcp_fail", "tcp", r["start"], r["end"], r["open"],
             "policy" if ext_ok else "with_outage",
             f"连续失败 {r['n']} 次" +
             ("; ICMP 正常而 TCP 失败 — 疑似端口策略/QoS" if ext_ok else ""))

    # 延迟突增
    for name, stream in (("gw", gw), ("ext", ext)):
        oks = [(s[1], s[2]) for s in stream if s[0] == "ok" and s[2] is not None]
        if len(oks) < 10:
            continue
        baseline = _monitor_pct([v for _, v in oks[:30]], 0.5)
        buckets = defaultdict(list)
        for t, v in oks:
            buckets[int(t // 10)].append(v)
        spike_buckets = []
        for b in sorted(buckets):
            p95 = _monitor_pct(buckets[b], 0.95)
            if p95 > max(3 * baseline, 200) and p95 > baseline + 50:
                spike_buckets.append((b * 10, p95))
        merged = []
        for sb, peak in spike_buckets:
            if merged and sb <= merged[-1][1] + 10:
                merged[-1][1] = sb + 10
                merged[-1][2] = max(merged[-1][2], peak)
            else:
                merged.append([sb, sb + 10, peak])
        for s0, s1, peak in merged:
            _add("latency_spike", name, s0, s1, False, "",
                 f"基线 {baseline:.0f}ms → 峰值 {peak:.0f}ms",
                 baseline=round(baseline, 1), peak=round(peak, 1))

    # 抖动窗口 (v1.5.2): 短窗口内丢包集中但未达连续中断 — 盯障最常遇到的形态
    for name, stream in (("gw", gw), ("ext", ext)):
        # v1.5.3: 重叠抑制只看本流的中断段 — 另一条流的中断与本流抖动是
        # 相互独立的证据, 跨流相切 1s 就整段吞掉 40s+ 抖动会丢关键事件
        outage_ranges = [(e["start_ts"], e["end_ts"]) for e in events
                         if e["type"] == "outage" and e.get("stream") == name]
        losses = [s[1] for s in stream if s[0] == "loss"]
        all_t = [s[1] for s in stream]
        for seg in _detect_jitter_segments(
                losses, all_t, MonitorSession.JITTER_WINDOW_S,
                MonitorSession.JITTER_STEP_S, MonitorSession.MIN_JITTER_LOSS,
                MonitorSession.MIN_JITTER_PCT, MonitorSession.MIN_JITTER_SAMPLES):
            s0, s1 = seg["start"], seg["end"]
            if any(so <= s1 and eo >= s0 for so, eo in outage_ranges):
                continue          # 本流中断段已覆盖, 不重复报抖动
            pct = seg["loss_pct"]
            # v1.5.3: detail 按段实际跨度描述 — 相邻触发窗口合并后可远超 60s,
            # 硬编码"60s 窗口"会与段时长矛盾 (合并段的口径丢包率也可能低于
            # 触发线, 不再引用"窗口"措辞)
            dur = max(1, int(round(s1 - s0)))
            if name == "ext":
                win0, win1 = s0 - 2, s1 + 2
                gw_loss_n = sum(1 for s in gw if s[0] == "loss"
                                and win0 <= s[1] <= win1)
                gw_ok_n = sum(1 for s in gw if s[0] == "ok"
                              and win0 <= s[1] <= win1)
                # v1.5.3: 网关 ≥2 次丢包才判 both_down — 单次孤立超时是背景
                # 噪声 (与中断判据的网关连续 ≥3 丢包同口径), 1 次就翻转定位
                # 会把运营商侧抖动误指向内网设备
                if gw_loss_n >= 2:
                    cls = "both_down"
                    detail = (f"{dur}s 内反复丢包 {seg['n_loss']}/{seg['n_total']} "
                              f"({pct}%), 网关同时丢包 {gw_loss_n} 次 — 链路/设备侧抖动")
                elif gw_ok_n >= 3:
                    cls = "carrier"
                    detail = (f"{dur}s 内反复丢包 {seg['n_loss']}/{seg['n_total']} "
                              f"({pct}%), 期间网关正常 — 运营商/上联侧抖动")
                else:
                    cls = "unknown"
                    detail = (f"{dur}s 内反复丢包 {seg['n_loss']}/{seg['n_total']} "
                              f"({pct}%), 网关数据不足")
            else:
                cls = "internal"
                detail = (f"{dur}s 内网关反复丢包 {seg['n_loss']}/{seg['n_total']} "
                          f"({pct}%) — 内网段抖动")
            _add("jitter_burst", name, s0, s1, False, cls, detail,
                 n_loss=seg["n_loss"], n_total=seg["n_total"], loss_pct=pct)

    # v1.7.0 (PR-F0): MTU 不匹配 — 路径 MTU 显著小于本机出口接口 (PMTUD 黑洞类
    # 故障的主动探测信号; ping 小包探测永远看不出, 这是盯障模式的关键补盲)。
    # 键可能缺失 (旧快照/单测合成输入), 用 .get 防御。
    mtu_info = snap.get("mtu") or {}
    if_mtu = mtu_info.get("local_if_mtu")
    worst = None       # 最受限通道: 所有有效 path_mtu 里的最小值
    for r in (mtu_info.get("path_mtus") or []):
        v = r.get("path_mtu")
        if v and (worst is None or v < worst[0]):
            worst = (v, r.get("target"))
    if worst and if_mtu and if_mtu - worst[0] >= MonitorSession.MTU_MISMATCH_MIN_DIFF:
        done_ts = mtu_info.get("done_ts") or ended_at
        _add("mtu_mismatch", "mtu", done_ts, done_ts, False, "mtu",
             f"路径 MTU {worst[0]} (到 {worst[1]}) < 本机接口 MTU {if_mtu} "
             f"(差 {if_mtu - worst[0]}) — 通道 MTU 受限 (运营商/VPN/物联网卡), "
             f"full-size 包可能被静默丢弃",
             path_mtu=worst[0], if_mtu=if_mtu)

    # v1.7.0 (PR-F0): TCP 重传爆发 — 会话差分口径 (区别于 diagnose 的开机累计),
    # 分母保护在 build_result 已做 (retrans_rate_pct 非 None 即分母足够)
    tq = snap.get("tcp_quality") or {}
    if tq.get("retrans_rate_pct") is not None \
            and tq["retrans_rate_pct"] >= MonitorSession.TCP_RETRANS_ERR_PCT:
        series = tq.get("series") or []
        s0 = series[0][0] if series else 0
        s1 = series[-1][0] if series else 0
        _add("tcp_retrans_burst", "tcpq", t0 + s0, t0 + s1, False, "l4_loss",
             f"盯障期间 TCP 重传率 {tq['retrans_rate_pct']}% "
             f"(重传 {tq.get('retrans_delta')} / 发送 {tq.get('sent_delta')}) — "
             f"传输层在丢包 (拥塞 / 链路质量 / MTU 不匹配)",
             retrans_rate_pct=tq["retrans_rate_pct"])

    events.sort(key=lambda e: e["start_ts"])
    for i, ev in enumerate(events, 1):
        ev["id"] = i
        ev["start_disp"] = _disp(ev["start_ts"])
        ev["end_disp"] = _disp(ev["end_ts"])
    return events


def _monitor_conclusion(events, stats, snap):
    """结论矩阵 (判定优先级自上而下) → (verdict, conclusion_text, advice)。"""
    def has(t, *cls):
        return [e for e in events
                if e["type"] == t and (not cls or e.get("cls") in cls)]

    internal = has("outage", "internal", "both_down")
    carrier = has("outage", "carrier")
    if any(e.get("cls") == "no_data" for e in events):
        return ("no_data", "监测未能采集到有效数据 (外网 ping 无输出)",
                "检查 ping 命令可用性; 必要时以管理员身份运行; "
                "更换 --monitor-target 后重试")
    if has("outage", "target_unreachable"):
        return ("target_unreachable",
                f"外网目标全程无 ICMP 回复, 但 TCP/DNS 正常",
                "目标可能禁 ping; 用 --monitor-target 119.29.29.29 等换目标复测")
    text_bits, advice_bits = [], []

    def _fmt_outages(lst, label):
        n = len(lst)
        total = sum(e["duration_s"] for e in lst)
        longest = max(e["duration_s"] for e in lst)
        open_mark = next((e for e in lst if e["open_at_end"]), None)
        s = (f"{label}中断 {n} 次 (累计 {total:.0f}s, 最长 {longest:.0f}s")
        s += ", 结束时仍未恢复)" if open_mark else ")"
        return s

    if internal or carrier:
        if internal and carrier:
            verdict = "mixed"
        else:
            verdict = "internal" if internal else "carrier"
        if internal:
            text_bits.append(_fmt_outages(internal, "本机到网关"))
            advice_bits.append("内网侧问题: 依次查 ①WiFi 信号/干扰或网线水晶头 "
                               "②路由器散热/重启路由器 ③光猫到路由器网线; "
                               "若光猫即网关且 LOS 红灯, 拍照后报障")
        if carrier:
            text_bits.append(_fmt_outages(carrier, "外网"))
            advice_bits.append("运营商侧问题: 检查光猫光衰/LOS 告警; 带上本 HTML 报告"
                               "向运营商报障 — 报告含分钟级时间轴, 可对齐客服记录")
    elif has("dns_fail", "dns"):
        verdict = "dns"
        n = len(has("dns_fail", "dns"))
        text_bits.append(f"DNS 解析失败 {n} 次, 期间外网 ping 正常")
        advice_bits.append("解析侧问题: 本机/路由器 DNS 改 223.5.5.5 与 "
                           "119.29.29.29 复测; 仍失败带报告报障")
    elif has("jitter_burst"):
        # v1.5.2: 无连续中断但短窗口内反复丢包 — 偶发掉线最典型形态
        verdict = "degraded"
        jbs = has("jitter_burst")
        ext_jb = [j for j in jbs if j["stream"] == "ext"]
        gw_jb = [j for j in jbs if j["stream"] == "gw"]
        pick = (max(ext_jb, key=lambda e: e.get("loss_pct", 0)) if ext_jb
                else max(gw_jb, key=lambda e: e.get("loss_pct", 0)))
        t0s = datetime.fromtimestamp(pick["start_ts"]).strftime("%H:%M:%S")
        t1s = datetime.fromtimestamp(pick["end_ts"]).strftime("%H:%M:%S")
        text_bits.append(
            f"无中断但抖动集中 {t0s}~{t1s}: "
            f"{'外网' if ext_jb else '网关'} {pick.get('n_loss')}/{pick.get('n_total')} 丢包 "
            f"({pick.get('loss_pct')}%)")
        if ext_jb and pick.get("cls") == "both_down":
            advice_bits.append(f"内外同抖 ({t0s}~{t1s}): 网关与外网同时丢包, 查光猫光衰/LOS 告警、"
                               "路由器日志; 将该时段与客户掉线记录对齐")
        elif ext_jb and pick.get("cls") == "carrier":
            advice_bits.append(f"上联/运营商侧抖动 ({t0s}~{t1s}): 网关正常但外网反复丢包, "
                               "查光猫光衰/LOS, 带报告报障并指出该时段")
        elif ext_jb:
            advice_bits.append(f"外网抖动 ({t0s}~{t1s}): 窗口内网关数据不足, "
                               "建议加长盯障 (如 --monitor 1800) 定位根因")
        else:
            advice_bits.append(f"内网段抖动 ({t0s}~{t1s}): 网关反复丢包, 查 WiFi 干扰/"
                               "网线水晶头/路由器负载")
    elif has("latency_spike"):
        verdict = "degraded"
        spikes = has("latency_spike")
        peak = max(s.get("peak", 0) for s in spikes)
        base = next((s.get("baseline", 0) for s in spikes), 0)
        text_bits.append(f"无中断但延迟突增 {len(spikes)} 段 "
                         f"(基线 {base:.0f}ms, 峰值 {peak:.0f}ms)")
        gw_spike = any(s["stream"] == "gw" for s in spikes)
        advice_bits.append(
            "本地段质量差 (网关线突增): 查 WiFi 干扰/网线" if gw_spike
            else "上行链路拥塞: 建议晚高峰复测对比, 结合 bufferbloat 模块")
    else:
        verdict = "stable"
        gw_pct = stats["gw"]["loss_pct"] if stats["gw"] else 0
        ext_pct = stats["ext"]["loss_pct"] if stats["ext"] else 0
        text_bits.append(f"监测期内未复现掉线 (网关丢包 {gw_pct:.1f}% / "
                         f"外网丢包 {ext_pct:.1f}%)")
        advice_bits.append("本次未复现: 建议在故障高发时段再盯 (如 --monitor 1800), "
                           "或请客户记录掉线时刻后与本报告时间轴对齐")
    # v1.7.0 (PR-F0): MTU / 传输层追加式结论 — 与任何 verdict 并存, stable 时升级
    mtu_evs = has("mtu_mismatch")
    rt_evs = has("tcp_retrans_burst")
    if mtu_evs:
        pm = mtu_evs[0].get("path_mtu")
        im = mtu_evs[0].get("if_mtu")
        if verdict == "stable":
            verdict = "degraded"
        text_bits.append(
            f"路径 MTU {pm} 小于本机接口 MTU {im} — 通道 MTU 受限, "
            f"full-size 包可能被静默丢弃 (ping 小包看不出, 视频卡顿/大文件慢的典型根因)")
        advice_bits.append(
            f"MTU 不匹配: 将电脑接口 MTU 改为 {pm} 后复跑盯障验证 — 管理员命令: "
            f"netsh interface ipv4 set subinterface \"接口名\" mtu={pm} store=persistent; "
            f"或联系运营商/检查中间设备启用 MSS clamping")
    if rt_evs:
        rate = rt_evs[0].get("retrans_rate_pct")
        if verdict == "stable":
            verdict = "degraded"
        text_bits.append(f"盯障期间 TCP 重传率 {rate}% — 传输层在丢包")
        if mtu_evs:
            advice_bits.append("重传与 MTU 不匹配同时出现: 大概率同源, 先按上方建议改 "
                               "MTU 再复测; 仍高再查链路质量")
        else:
            advice_bits.append("MTU 正常而重传率超标: 运营商链路质量/拥塞问题, "
                               "带上本报告 (含重传时序) 报障")
    return verdict, "；".join(text_bits), "\n".join(advice_bits)


class MonitorSession:
    """盯障会话: 4 路采集 + 进度行 + 网关漂移复查。"""

    PROBE_INTERVAL = 5.0      # TCP/DNS 探测周期
    GAP_S = 10.0              # ping 流静默判定间隙 (全丢包时超时行 ~2s/行)
    MIN_LOSS_BURST = 3        # 连续丢包 ≥3 (~3s) 判中断
    MIN_DNS_FAIL = 2          # DNS 连续失败 ≥2 (~10s) 判事件
    DNS_DOMAIN = "www.qq.com"
    JITTER_WINDOW_S = 60      # 抖动窗口宽度 (秒)
    JITTER_STEP_S = 10        # 抖动触发窗口的合并间隔 (秒, ≤ 此间隔视为同一段)
    MIN_JITTER_LOSS = 3       # 窗口内丢包 ≥3 次判抖动 (与 MIN_LOSS_BURST 对齐)
    MIN_JITTER_PCT = 10.0     # 窗口内丢包率 ≥10% 判抖动 (还需丢包 ≥2 次, 见下)
    MIN_JITTER_SAMPLES = 10   # 丢包率判据的最小窗口样本数 (分母更小只按次数判)

    # v1.7.0 (PR-F0): 统计层常量 — 盯障模式的 L4 眼睛
    TCPSTAT_INTERVAL_S = 30          # TCP 重传统计采样周期 (开机累计计数器, 差分出会话口径)
    TCPSTAT_MIN_SENT_DELTA = 5000    # 分母保护: 会话发送增量低于此值不判重传率
    MTU_MISMATCH_MIN_DIFF = 100      # 接口 MTU − 路径 MTU ≥ 此值才判不匹配 (PPPoE 1492 不误报)
    TCP_RETRANS_ERR_PCT = 5.0        # 会话重传率阈值 (与 diagnose tcpstats err 档一致)
    MONITOR_LOAD_URL = "https://dldir1.qq.com/weixin/Windows/WeChatSetup.exe"
    LOAD_DELAY_S = 60                # 主动负载延迟启动 (先让盯障跑起来, 避开启动期噪声)
    LOAD_DURATION_S = 15             # 主动负载读取时长 (读即丢弃, 不落盘)

    def __init__(self, duration_s, ext_target=None, load_url=None):
        self.duration_s = duration_s
        self.ext_target = ext_target or "223.5.5.5"
        self._load_url = load_url
        self._stop = threading.Event()
        self._gw_monitors = []        # [(ip, LatencyMonitor)] 支持漂移后多段
        self._ext_monitor = None
        self._probe_thread = None
        self._tcp_samples = []        # [(t, ms_or_None)]
        self._dns_samples = []        # [(t, ms_or_None, ip)]
        self._probe_lock = threading.Lock()
        self._gw_ip = None
        self._dns_server = None
        self._t0 = None
        self._notes = []
        self._last_gw_check = 0.0
        self._mtu_thread = None       # 后台路径 MTU 探测 (PR-F0)
        self._mtu_result = None       # {"path_mtus": [...], "local_if_mtu": N, ...}
        self._mtu_done = threading.Event()
        self._tcpstat_thread = None   # 周期 TCP 重传统计采样 (PR-F0)
        self._tcpstat_samples = []    # [(t, sent, retrans)] 开机累计计数器

    def note(self, text):
        self._notes.append({"t": round(time.time() - self._t0, 1) if self._t0 else 0,
                            "text": text})

    def start(self):
        self._t0 = time.time()
        self._gw_ip = get_default_gateway()
        self._dns_server = (get_dns_servers() or ["223.5.5.5"])[0]
        # 域名目标先解析 (DNS 挂了也不至于 ping 不动)
        target = self.ext_target
        try:
            socket.inet_aton(target)
        except OSError:
            try:
                target = socket.getaddrinfo(target, 0, socket.AF_INET)[0][4][0]
                self.note(f"外网目标 {self.ext_target} 解析为 {target}")
            except Exception as e:
                self.note(f"外网目标 {self.ext_target} 解析失败: {e}")
        self._ext_ip_resolved = target
        if self._gw_ip:
            mon = LatencyMonitor(self._gw_ip)
            if mon.start():
                self._gw_monitors.append((self._gw_ip, mon))
            else:
                self.note(f"网关 ping 启动失败 ({self._gw_ip})")
        else:
            self.note("未取到默认网关, 网关路缺席")
        self._ext_monitor = LatencyMonitor(target)
        if not self._ext_monitor.start():
            return False
        self._probe_thread = threading.Thread(target=self._probe_loop, daemon=True)
        self._probe_thread.start()
        # v1.7.0 (PR-F0): 统计层 — 后台路径 MTU 探测 (网关 + 外网目标)。
        # 二分探测最坏 ~30s, 放后台不阻塞盯障启动; build_result 时最多等 10s 取结果。
        mtu_targets = []
        if self._gw_ip:
            mtu_targets.append(self._gw_ip)
        if self._ext_ip_resolved and self._ext_ip_resolved not in mtu_targets:
            mtu_targets.append(self._ext_ip_resolved)
        if mtu_targets:
            self._mtu_thread = threading.Thread(
                target=self._mtu_probe_worker, args=(mtu_targets,), daemon=True)
            self._mtu_thread.start()
        # TCP 重传统计采样 (独立线程: PowerShell 冷启动 1-2s, 不拖累 DNS/TCP 探测节拍)
        self._tcpstat_thread = threading.Thread(target=self._tcpstat_loop, daemon=True)
        self._tcpstat_thread.start()
        if self._load_url:
            threading.Thread(target=self._load_worker, daemon=True).start()
        atexit.register(self.stop)          # 兜底: 进程被硬杀前尽量收 ping
        return True

    def _probe_loop(self):
        first = True
        while not self._stop.is_set():
            t_iter = time.time()
            try:
                # 排空上一轮迟到的 DNS 应答 (线程本地 socket 复用的串轮防护)
                s = _get_dns_socket(0.02)
                if s is not None:
                    try:
                        s.settimeout(0.02)
                        while True:
                            s.recvfrom(2048)
                    except Exception:
                        pass
                t = time.time()
                ip, ms = _dns_query(self._dns_server, self.DNS_DOMAIN, timeout=2.5)
                with self._probe_lock:
                    self._dns_samples.append((t, ms, ip))
                if self._stop.is_set():
                    break
                ms2 = _tcping_ms(f"{self._ext_ip_resolved}:53", timeout=3.0)
                with self._probe_lock:
                    self._tcp_samples.append((time.time(), ms2))
            except Exception:
                pass
            if first:
                first = False
                continue                      # 首轮后立即进入节拍
            self._stop.wait(max(0.0, self.PROBE_INTERVAL - (time.time() - t_iter)))

    def _mtu_probe_worker(self, targets):
        """后台路径 MTU 探测 (PR-F0): 复用 diagnose 的 _probe_path_mtu,
        目标为网关 + 外网目标 (而非 diagnose 固定的 223.5.5.5)。"""
        t_start = time.time()
        err = None
        path_mtus = []
        try:
            with ThreadPoolExecutor(max_workers=min(2, len(targets))) as ex:
                for r in ex.map(_probe_path_mtu, targets):
                    path_mtus.append(r)
        except Exception as e:
            err = f"MTU 探测线程异常: {e}"
        local_if_mtu, local_if_name = None, ""
        if not err:
            try:
                local_if_mtu, local_if_name = _default_route_if_mtu()
            except Exception:
                pass
        self._mtu_result = {
            "path_mtus": path_mtus,
            "local_if_mtu": local_if_mtu,
            "local_if_name": local_if_name,
            "probe_s": round(time.time() - t_start, 1),
            "done_ts": time.time(),
            "error": err,
        }
        self._mtu_done.set()

    def _tcpstat_loop(self):
        """周期采样 TCP 重传统计 (PR-F0): 开机累计计数器, 会话口径由
        build_result 做差分。首采立即执行 (baseline 越早, 差分窗口越长)。"""
        while not self._stop.is_set():
            t = time.time()
            try:
                s = _tcp_stats_snapshot()
                sent, retrans = s.get("segments_sent"), s.get("retransmitted")
                if sent is not None and retrans is not None:
                    with self._probe_lock:
                        self._tcpstat_samples.append((t, sent, retrans))
            except Exception:
                pass
            self._stop.wait(self.TCPSTAT_INTERVAL_S)

    def _load_worker(self):
        """主动负载 (--monitor-load, PR-F0): 流式读大文件即丢弃, 制造
        full-size 数据包让 TCP 重传统计有分子分母。仅内存中转, 不落盘。"""
        import urllib.request
        self._stop.wait(self.LOAD_DELAY_S)
        if self._stop.is_set():
            return
        n_bytes, t0 = 0, time.time()
        try:
            req = urllib.request.Request(
                self._load_url, headers={"User-Agent": "NetPulse-MonitorLoad"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                while (time.time() - t0 < self.LOAD_DURATION_S
                       and not self._stop.is_set()):
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    n_bytes += len(chunk)
            self.note(f"主动负载: {self.LOAD_DURATION_S}s 读取 "
                      f"{n_bytes / 1048576:.1f} MB (仅制造流量, 未落盘)")
        except Exception as e:
            self.note(f"主动负载失败: {e}")

    def maybe_recheck_gateway(self, elapsed):
        """每 60s 复查网关 (用户切 WiFi/换路由时旧网关会永久假丢包)。"""
        if elapsed - self._last_gw_check < 60:
            return
        self._last_gw_check = elapsed
        try:
            gw = get_default_gateway()
        except Exception:
            return
        if gw and gw != self._gw_ip:
            self.note(f"网关漂移: {self._gw_ip} → {gw}, 已切换监测")
            for _ip, mon in self._gw_monitors:
                mon.stop()
            self._gw_ip = gw
            mon = LatencyMonitor(gw)
            if mon.start():
                self._gw_monitors.append((gw, mon))

    def snapshot(self):
        gw_stream = []
        for _ip, mon in self._gw_monitors:
            gw_stream.extend(mon.stream_since())
        gw_stream.sort(key=lambda s: s[1])
        ext_stream = self._ext_monitor.stream_since() if self._ext_monitor else []
        with self._probe_lock:
            tcp = list(self._tcp_samples)
            dns = list(self._dns_samples)
        return {"gw_stream": gw_stream, "ext_stream": ext_stream,
                "tcp": tcp, "dns": dns}

    def progress_line(self, elapsed):
        now = time.time()
        gw_loss = sum(1 for _ip, m in self._gw_monitors
                      for t in m.losses_since(now - 10))
        ext_loss = len(self._ext_monitor.losses_since(now - 10)) \
            if self._ext_monitor else 0
        with self._probe_lock:
            last_dns = self._dns_samples[-1] if self._dns_samples else None
            last_tcp = self._tcp_samples[-1] if self._tcp_samples else None
        # 无样本 (刚启动) 显示 …, 有样本才判 ✓/✗
        dns_ok = last_dns is not None and last_dns[1] is not None
        tcp_ok = last_tcp is not None and last_tcp[1] is not None
        dns_disp = "…" if last_dns is None else ("✓" if dns_ok else "✗")
        tcp_disp = "…" if last_tcp is None else ("✓" if tcp_ok else "✗")
        gw_bad = gw_loss >= self.MIN_LOSS_BURST
        ext_bad = ext_loss >= self.MIN_LOSS_BURST
        # 轻量事件计数: 连续丢包段数 (与最终落盘口径一致)
        snap = self.snapshot()
        ev_n = (len(_merge_runs(_strip_gaps(snap["gw_stream"], self.GAP_S)[0],
                                self.MIN_LOSS_BURST, now))
                + len(_merge_runs(_strip_gaps(snap["ext_stream"], self.GAP_S)[0],
                                  self.MIN_LOSS_BURST, now)))
        return (f"  盯障中 {_c(f'{elapsed:.0f}', C_CYAN)}/{self.duration_s}s  "
                f"网关 {_c('✗丢' + str(gw_loss), C_RED) if gw_bad else _c('✓', C_GREEN)}  "
                f"外网 {_c('✗丢' + str(ext_loss), C_RED) if ext_bad else _c('✓', C_GREEN)}  "
                f"DNS {_c(dns_disp, C_GREEN if dns_ok else C_GRAY if last_dns is None else C_RED)}  "
                f"TCP {_c(tcp_disp, C_GREEN if tcp_ok else C_GRAY if last_tcp is None else C_RED)}  "
                f"事件 {_c(str(ev_n), C_YELLOW) if ev_n else '0'} 起"
                f"  {_c('(Ctrl+C 提前结束)', C_GRAY)}")

    def stop(self):
        if self._stop.is_set():           # 幂等
            return
        self._stop.set()
        for _ip, mon in self._gw_monitors:
            mon.stop()
        if self._ext_monitor:
            self._ext_monitor.stop()
        if self._probe_thread:
            self._probe_thread.join(timeout=2)
        if self._tcpstat_thread:
            self._tcpstat_thread.join(timeout=2)
        # MTU 探测线程不 join: 二分探测最坏 ~30s, 提前结束时由 build_result
        # 的 _mtu_done.wait(10) 决定等不等 (daemon, 不阻塞进程退出)

    def _tcpstat_quality(self):
        """TCP 重传会话差分 (v1.7.0): build_result 的权威口径与抓包层
        poll_events 的增量检测共用, 避免两处判据漂移。
        分母保护: sent 增量 < TCPSTAT_MIN_SENT_DELTA 时机器空闲, 单个重传
        就能把比率冲高, 只展示原始增量不判比率 (retrans_rate_pct=None)。"""
        with self._probe_lock:
            series = list(self._tcpstat_samples)
        tq = {"series": [], "sent_delta": 0, "retrans_delta": 0,
              "retrans_rate_pct": None, "samples": len(series)}
        if len(series) >= 2:
            sent_delta = series[-1][1] - series[0][1]
            retrans_delta = series[-1][2] - series[0][2]
            if sent_delta >= 0:
                tq["sent_delta"] = sent_delta
                tq["retrans_delta"] = retrans_delta
                tq["series"] = [[round(t - self._t0, 1), s, r]
                                for t, s, r in series]
                if sent_delta >= self.TCPSTAT_MIN_SENT_DELTA:
                    tq["retrans_rate_pct"] = round(
                        retrans_delta / sent_delta * 100, 2)
        return tq

    @staticmethod
    def _stream_stats(stream):
        ok_vals = [s[2] for s in stream if s[0] == "ok" and s[2] is not None]
        loss_n = sum(1 for s in stream if s[0] == "loss")
        total = ok_vals and len(ok_vals) + loss_n
        if not total:
            return {"ok": 0, "loss": 0, "loss_pct": 0.0, "avg_ms": None,
                    "p50_ms": None, "p95_ms": None, "max_ms": None}
        return {"ok": len(ok_vals), "loss": loss_n,
                "loss_pct": round(loss_n / total * 100, 2),
                "avg_ms": round(sum(ok_vals) / len(ok_vals), 1) if ok_vals else None,
                "p50_ms": round(_monitor_pct(ok_vals, 0.5), 1) if ok_vals else None,
                "p95_ms": round(_monitor_pct(ok_vals, 0.95), 1) if ok_vals else None,
                "max_ms": round(max(ok_vals), 1) if ok_vals else None}

    def build_result(self, early_terminated=False):
        ended_at = time.time()
        duration_actual = round(ended_at - self._t0)
        # v1.7.0 (PR-F0): MTU 探测仍在跑时最多等 10s (二分最坏 ~30s,
        # 超时则报告标注未完成, 不无限拖住报告落盘)
        if self._mtu_thread and self._mtu_thread.is_alive():
            self._mtu_done.wait(10)
        snap = self.snapshot()

        def _probe_stats(samples):
            ok = [s[1] for s in samples if s[1] is not None]
            fail = len(samples) - len(ok)
            return {"ok": len(ok), "fail": fail,
                    "ok_pct": round(len(ok) / len(samples) * 100, 1) if samples else 0.0,
                    "avg_ms": round(sum(ok) / len(ok), 1) if ok else None}

        stats = {"gw": self._stream_stats(snap["gw_stream"]),
                 "ext": self._stream_stats(snap["ext_stream"]),
                 "tcp": _probe_stats(snap["tcp"]),
                 "dns": _probe_stats(snap["dns"])}
        t0 = self._t0
        # v1.7.0 (PR-F0): MTU 探测结果块 (probe_status: ok / error / timeout / skipped)
        mtu_raw = self._mtu_result
        if mtu_raw and not mtu_raw.get("error"):
            mtu_status = "ok"
        elif mtu_raw:
            mtu_status = "error"
        elif self._mtu_thread and self._mtu_thread.is_alive():
            mtu_status = "timeout"
        else:
            mtu_status = "skipped"
        mtu_block = dict(mtu_raw or {})
        mtu_block["probe_status"] = mtu_status
        # v1.7.0 (PR-F0): TCP 重传会话差分 (开机累计计数器 → 会话口径)。
        with self._probe_lock:
            tcpstat_series = list(self._tcpstat_samples)
        tq = self._tcpstat_quality()
        snap["mtu"] = mtu_block
        snap["tcp_quality"] = tq
        events = _detect_monitor_events(snap, self._t0, ended_at)
        verdict, conclusion, advice = _monitor_conclusion(events, stats, snap)

        result = {
            "mode": "monitor",
            "timestamp": datetime.fromtimestamp(t0).isoformat(),
            "started_at": datetime.fromtimestamp(t0).strftime("%Y-%m-%d %H:%M:%S"),
            "ended_at": datetime.fromtimestamp(ended_at).strftime("%Y-%m-%d %H:%M:%S"),
            "duration_planned_s": self.duration_s,
            "duration_actual_s": duration_actual,
            "early_terminated": early_terminated,
            "targets": {"gateway": self._gw_ip,
                        "external": self.ext_target,
                        "external_resolved": self._ext_ip_resolved,
                        "tcp_target": f"{self._ext_ip_resolved}:53",
                        "dns_server": self._dns_server,
                        "dns_domain": self.DNS_DOMAIN},
            "notes": self._notes,
            "samples": {
                "gw_rtt": [[round(s[1] - t0, 1), round(s[2], 1)]
                           for s in snap["gw_stream"] if s[0] == "ok"],
                "gw_loss": [round(s[1] - t0, 1)
                            for s in snap["gw_stream"] if s[0] == "loss"],
                "ext_rtt": [[round(s[1] - t0, 1), round(s[2], 1)]
                            for s in snap["ext_stream"] if s[0] == "ok"],
                "ext_loss": [round(s[1] - t0, 1)
                             for s in snap["ext_stream"] if s[0] == "loss"],
                "tcp": [[round(s[0] - t0, 1), round(s[1], 1) if s[1] is not None else None]
                        for s in snap["tcp"]],
                "dns": [[round(s[0] - t0, 1),
                         round(s[1], 1) if s[1] is not None else None, s[2]]
                        for s in snap["dns"]],
            },
            "stats": stats,
            "mtu": mtu_block,
            "tcp_quality": tq,
            "events": events,
            "verdict": verdict,
            "conclusion_text": conclusion,
            "advice": advice,
            "local_ip": get_local_ip(),
        }
        # 阶段 D · v1.4.0: 给每个事件附 root_cause 标签 (D5)
        # 把已有的 cls 字段翻译为客户可读的根因描述.
        _CLS_TO_ROOT_CAUSE = {
            "internal": "LAN/WiFi 内网中断 (网关不可达)",
            "carrier":  "运营商 WAN 中断 (网关可达但外网不通)",
            "both_down": "网关 + 外网同时中断 (内网/WAN 都可能)",
            "unknown":  "根因未知 (网关数据缺失)",
            "dns":      "DNS 解析故障",
            "policy":   "疑似端口策略 / QoS (信息级)",
            # classify_event 的另三类 cls (v1.4.1 前落到"其他")
            "target_unreachable": "外网目标不可达 (网关正常, 目标或出口链路问题)",
            "no_data":  "无有效采样 (外网 ping 无输出, 采集失败/系统睡眠?)",
            "with_outage": "异常随中断出现 (DNS/端口异常与掉线同时发生)",
            # v1.7.0 (PR-F0): 统计层新事件的定位
            "mtu":      "MTU 不匹配 (路径 MTU 小于本机接口, full-size 包可能被静默丢弃)",
            "l4_loss":  "TCP 传输层丢包 (会话重传率超标)",
        }
        for ev in events:
            cls = ev.get("cls", "")
            if ev.get("type") == "monitor_gap":
                ev["root_cause"] = "采集间隙 (系统睡眠/进程阻塞?)"
            elif ev.get("type") == "jitter_burst":
                ev["root_cause"] = {
                    "both_down": "内外同抖 (链路/设备侧)",
                    "carrier": "运营商/上联侧抖动",
                    "internal": "内网段抖动",
                    "unknown": "抖动根因未知",
                }.get(cls, "抖动集中")
            elif cls in _CLS_TO_ROOT_CAUSE:
                ev["root_cause"] = _CLS_TO_ROOT_CAUSE[cls]
            else:
                ev["root_cause"] = "其他"
        # CSV 行 (绝对墙钟, Excel 直开)
        rows = []
        for probe, stream, note_fn in (
                ("gw_ping", snap["gw_stream"],
                 lambda s: "" if s[0] == "ok" else "timeout"),
                ("ext_ping", snap["ext_stream"],
                 lambda s: "" if s[0] == "ok" else "timeout"),
                ("ext_tcp", snap["tcp"],
                 lambda s: "" if s[1] is not None else "connect_fail"),
                ("dns", snap["dns"],
                 lambda s: s[2] or "resolve_fail")):
            for i, s in enumerate(stream, 1):
                ts = s[1] if probe.endswith("ping") else s[0]
                val = (s[2] if probe.endswith("ping") else s[1])
                rows.append([datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                             probe, i,
                             round(val, 1) if isinstance(val, (int, float)) else "",
                             1 if (val is not None) else 0, note_fn(s)])
        # v1.7.0 (PR-F0): TCP 重传采样行 (区间差分口径, 与 ping 类并列)
        for i in range(1, len(tcpstat_series)):
            _tp, _sp, _rp = tcpstat_series[i - 1]
            _tc, _sc, _rc = tcpstat_series[i]
            ds, dr = _sc - _sp, _rc - _rp
            rows.append([datetime.fromtimestamp(_tc).strftime("%Y-%m-%d %H:%M:%S"),
                         "tcp_retrans", i,
                         round(dr / ds * 100, 2) if ds > 0 else "",
                         1, f"retrans {dr}/{ds}"])
        result["_csv_rows"] = rows
        outages = [e for e in events if e["type"] == "outage"]
        jitters = [e for e in events if e["type"] == "jitter_burst"]
        summary_bits = [f"盯障 {duration_actual}s: 网关丢包 {stats['gw']['loss_pct']}%, "
                        f"外网丢包 {stats['ext']['loss_pct']}%"]
        if outages:
            summary_bits.append(f"中断 {len(outages)} 起 (最长 "
                                f"{max(e['duration_s'] for e in outages):.0f}s)")
        else:
            summary_bits.append("无中断")
        if jitters:
            summary_bits.append(f"抖动集中 {len(jitters)} 段")
        summary_bits.append(f"DNS 失败 {stats['dns']['fail']} 次")
        if tq["retrans_rate_pct"] is not None:
            summary_bits.append(f"TCP 重传率 {tq['retrans_rate_pct']}%")
        if any(e["type"] == "mtu_mismatch" for e in events):
            summary_bits.append("路径 MTU 受限")
        result["summary"] = ", ".join(summary_bits)
        return result


def save_monitor_report(res):
    """盯障三件套: CSV (utf-8-sig, Excel 直开) + HTML + JSON。返回 (html, json) 或 None。"""
    try:
        day_dir = _report_dir()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(day_dir, f"monitor_{stamp}.csv")
        json_path = os.path.join(day_dir, f"monitor_{stamp}.json")
        html_path = os.path.join(day_dir, f"monitor_{stamp}.html")
        rows = res.pop("_csv_rows", [])
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            w = _csv.writer(f)
            w.writerow(["time", "probe", "seq", "value_ms", "ok", "note"])
            w.writerows(rows)
        snapshot = dict(res)
        snapshot["report_html"] = html_path
        snapshot["report_csv"] = csv_path
        snapshot["report_json"] = json_path
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2, default=str)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(_render_monitor_html(snapshot))
        return html_path, json_path
    except Exception:
        return None


def _render_monitor_html(res):
    """盯障独立报告: 结论 banner (会诊核心) + 事件表 + 延迟时序双线 (中断色带) +
    连通率图。完全离线 (canvas 手绘, 无外部依赖)。"""
    stats = res.get("stats", {})
    events = res.get("events", [])
    tg = res.get("targets", {})
    samples = res.get("samples", {})
    early = " · <b>提前结束</b>" if res.get("early_terminated") else ""
    dur = (f"{res.get('duration_actual_s')}s / 计划 {res.get('duration_planned_s')}s"
           f"{early}")

    def _downsample(series, cap=2000):
        if len(series) <= cap:
            return series
        import math
        bucket = math.ceil(len(series) / cap)
        out = []
        for i in range(0, len(series), bucket):
            chunk = series[i:i + bucket]
            out.append([chunk[0][0],
                        round(sum(v for _, v in chunk) / len(chunk), 1)])
        return out

    def _bands(loss_offsets, merge_s=1.0):
        if not loss_offsets:
            return []
        bands = []
        s = p = loss_offsets[0]
        for t in loss_offsets[1:]:
            if t - p <= merge_s + 1.5:
                p = t
            else:
                bands.append([s, p])
                s = p = t
        bands.append([s, p])
        return bands

    gw = _downsample(samples.get("gw_rtt") or [])
    ext = _downsample(samples.get("ext_rtt") or [])

    def _rate_series(probe_samples, bucket_s=30):
        buckets = defaultdict(lambda: [0, 0])
        for item in probe_samples:
            b = int(item[0] // bucket_s)
            buckets[b][0] += 1 if item[1] is not None else 0
            buckets[b][1] += 1
        return [[b * bucket_s, round(c / n * 100, 1)]
                for b, (c, n) in sorted(buckets.items()) if n]

    tcp_rate = _rate_series(samples.get("tcp") or [])
    dns_rate = _rate_series(samples.get("dns") or [])
    # v1.7.0 (PR-F0): TCP 重传率时序 (相邻采样点差分, 与 CSV tcp_retrans 行同口径)
    tq = res.get("tcp_quality") or {}
    tq_series = tq.get("series") or []
    retrans_rate_series = []
    for i in range(1, len(tq_series)):
        ds = tq_series[i][1] - tq_series[i - 1][1]
        dr = tq_series[i][2] - tq_series[i - 1][2]
        if ds > 0:
            retrans_rate_series.append([tq_series[i][0], round(dr / ds * 100, 2)])
    if tq.get("retrans_rate_pct") is not None:
        tq_rate_html = (f"{tq['retrans_rate_pct']}% (重传 {tq.get('retrans_delta')} / "
                        f"发送 {tq.get('sent_delta')})")
    elif tq_series:
        tq_rate_html = f"分母不足 (发送增量 {tq.get('sent_delta', 0)} 段), 不判比率"
    else:
        tq_rate_html = "无采样"
    tq_rate_pct = tq.get("retrans_rate_pct")
    # v1.7.0 (PR-F0): MTU 探测结果行 (path_mtus 每目标一行)
    mtu = res.get("mtu") or {}
    mtu_rows = []
    for r in (mtu.get("path_mtus") or []):
        tgt = _esc_html(str(r.get("target")))
        if r.get("error"):
            mtu_rows.append(f"<tr><td>路径 MTU (到 {tgt})</td>"
                            f"<td>探测失败: {_esc_html(str(r.get('error')))}</td></tr>")
        else:
            mtu_rows.append(f"<tr><td>路径 MTU (到 {tgt})</td>"
                            f"<td>{r.get('path_mtu', '—')} (探测 {r.get('probes', '—')} 次)</td></tr>")
    if_mtu = mtu.get("local_if_mtu")
    if if_mtu:
        mtu_local_html = (f"<tr><td>本机出口接口 MTU</td><td>{if_mtu}"
                          + (f" ({_esc_html(str(mtu.get('local_if_name')))})"
                             if mtu.get("local_if_name") else "")
                          + "</td></tr>")
    else:
        mtu_local_html = "<tr><td>本机出口接口 MTU</td><td>未获取</td></tr>"
    data_js = json.dumps({
        "gw": gw, "ext": ext,
        "gw_bands": _bands(samples.get("gw_loss") or []),
        "ext_bands": _bands(samples.get("ext_loss") or []),
        "tcp_rate": tcp_rate, "dns_rate": dns_rate,
        "retrans_rate": retrans_rate_series,
    }, ensure_ascii=False)

    gw_pct = stats.get("gw", {}).get("loss_pct", 0)
    ext_pct = stats.get("ext", {}).get("loss_pct", 0)
    outages = [e for e in events if e["type"] == "outage"]
    longest = max((e["duration_s"] for e in outages), default=0)
    dns_ok = stats.get("dns", {}).get("ok_pct")

    def _metric(label, value, level, note=""):
        # 与主报告指标卡同向: 数值在上、名称在下
        color = {"ok": "#0e8a4f", "warn": "#b26a00", "err": "#b42318"}[level]
        note_html = f"<div class='note'>{_esc_html(note)}</div>" if note else ""
        return (f"<div class='metric'>"
                f"<div class='v' style='color:{color}'>{_esc_html(value)}</div>"
                f"<div class='lab'>{_esc_html(label)}</div>"
                f"{note_html}</div>")

    v_color = {"stable": "#0e8a4f", "no_data": "#64748b", "target_unreachable": "#b26a00",
               "internal": "#b42318", "carrier": "#b42318", "dns": "#b26a00",
               "degraded": "#b26a00", "mixed": "#b42318"}.get(res.get("verdict"), "#0e8a4f")
    v_name = {"stable": "监测稳定", "no_data": "无有效数据", "target_unreachable": "目标不可达",
              "internal": "内网侧问题", "carrier": "运营商侧问题", "dns": "解析侧问题",
              "degraded": "质量劣化", "mixed": "混合问题"}.get(res.get("verdict"), "")
    # v1.8.0 (PR-F4): 抓包证据置信度徽标 (无抓包佐证时不出该行)
    conf_html = ""
    if res.get("confidence"):
        # v1.9.1: 抓包置信度是 0-100 百分数, 先归一到 0-1 再分档
        # (审查修复: 原先 85/92 碰巧落"高", 但 1-74 区间会全部误判"高置信度")
        conf_html = (f"<div class='conf'>🎯 结论{_conf_band(res.get('confidence') / 100)} — "
                     f"{_esc_html(str(res.get('confidence_basis', '')))}</div>")

    ev_rows = []
    type_names = {"outage": "中断", "dns_fail": "DNS 故障", "tcp_fail": "TCP 失败",
                  "latency_spike": "延迟突增", "jitter_burst": "抖动集中",
                  "monitor_gap": "采集间隙",
                  # v1.7.0 (PR-F0): 统计层新事件
                  "mtu_mismatch": "MTU 不匹配", "tcp_retrans_burst": "TCP 重传爆发"}
    cls_names = {"internal": "内网侧", "carrier": "运营商侧", "both_down": "内外同断",
                 "dns": "解析侧", "with_outage": "随中断", "policy": "端口策略",
                 "target_unreachable": "目标不可达", "unknown": "无法定位", "": "",
                 "mtu": "MTU 受限", "l4_loss": "传输层丢包"}
    for e in events:
        if e["type"] == "monitor_gap":
            continue
        status = ("<span class='pill open'>结束时未恢复</span>" if e.get("open_at_end")
                  else "<span class='pill ok'>已恢复</span>")
        # v1.8.0 (PR-F2): 事件挂了切片时给取证链接 (Wireshark 可直接打开)
        if e.get("pcap_slice"):
            href = str(e["pcap_slice"]).replace("\\", "/")
            status += (f"<br><a href='{href}' style='font-size:11px'>"
                       f"📁 抓包切片</a>")
        # v1.8.0 (PR-F4): 抓包证据确认的根因 → 徽标 (定位列同步展示)
        if e.get("pcap_evidence"):
            status += (f"<br><span class='pill' "
                       f"style='background:#eef2ff;color:#4338ca'>"
                       f"🔬 {_esc_html(e['pcap_evidence'])}</span>")
        # v1.8.0 (PR-F4): 抓包佐证的根因 → 定位列加 "🔬 抓包分析" 标记
        cls_cell = _esc_html(cls_names.get(e.get('cls', ''), e.get('cls', '—')))
        if e.get("pcap_evidence"):
            cls_cell += (f" <span class='pill' style='background:#eef2ff;"
                         f"color:#4338ca'>🔬 抓包分析</span>")
        ev_rows.append(
            f"<tr><td>{_esc_html(e['start_disp'])}–{_esc_html(e['end_disp'])}</td>"
            f"<td>{e['duration_s']:.0f}s</td>"
            f"<td>{type_names.get(e['type'], e['type'])}</td>"
            f"<td>{cls_cell}</td>"
            f"<td>{_esc_html(e.get('detail', ''))}</td><td>{status}</td></tr>")
    ev_table = ("<table><tr><th>时刻</th><th>持续</th><th>类型</th><th>定位</th>"
                "<th>详情</th><th>状态</th></tr>"
                + ("".join(ev_rows) if ev_rows
                   else "<tr><td colspan=6 class='empty'>监测期内无异常事件</td></tr>")
                + "</table>")

    notes_html = "".join(f"<div class='note-line'>· [{n['t']}s] {_esc_html(n['text'])}</div>"
                         for n in res.get("notes", []))
    # v1.8.0 (PR-F1/F2): 抓包取证面板 — 切片清单/全程 pcap/隐私与清理声明
    cap = res.get("capture") or {}
    cap_panel = ""
    if cap:
        _slice_rows = []
        for s in (cap.get("slices") or []):
            href = s.get("rel") or s.get("path") or ""
            _slice_rows.append(
                f"<tr><td>{_esc_html(str(s.get('ts', '')))}</td>"
                f"<td>{_esc_html(type_names.get(s.get('event_type', ''),
                                               s.get('event_type', '—')))}</td>"
                f"<td>{s.get('pkts', 0)} 包</td>"
                f"<td><a href='{href}'>{_esc_html(str(s.get('path', '')))}</a></td></tr>")
        _full_html = ""
        if cap.get("full_pcap"):
            _fhref = cap.get("full_pcap_rel") or cap.get("full_pcap")
            _full_html = (f"<tr><td>全程抓包</td><td colspan=3>"
                          f"<a href='{_fhref}'>{_esc_html(str(cap['full_pcap']))}</a>"
                          f" ({cap.get('packets_captured', 0)} 包)</td></tr>")
        # v1.8.0 (PR-F4): 切片离线分析结论行
        _ana = cap.get("analysis") or {}
        _ana_rows = ""
        if _ana:
            _stalls = [s for s in (_ana.get("streams") or [])
                       if s.get("fullsize_stall")]
            _frag = _ana.get("icmp_frag_needed") or []
            _sni = [s for s in (_ana.get("tls_sni") or []) if s != "sni_truncated"]
            _trunc = sum(1 for s in (_ana.get("tls_sni") or [])
                         if s == "sni_truncated")
            _bits = []
            if _ana.get("suspected_pmtud_blackhole"):
                _bits.append("<b style='color:#b42318'>疑似 PMTU 黑洞 (三信号判定)</b>")
            if _ana.get("suspected_tcp_loss_burst"):
                _bits.append("<b style='color:#b26a00'>疑似链路丢包/拥塞</b>")
            if _ana.get("suspected_dns_slow"):
                _bits.append("<b style='color:#b26a00'>DNS 慢查询</b>")
            _line1 = ("；".join(_bits) if _bits
                      else "未见 PMTU 黑洞 / 链路丢包 / DNS 慢查询类证据")
            _lines = [_line1,
                      f"重传 {_ana.get('tcp_retransmit_count', 0)} 段 "
                      f"(占比 {_ana.get('retrans_rate', 0) * 100:.1f}%) · "
                      f"dup-ack {_ana.get('tcp_dup_ack_count', 0)} · "
                      f"RST {_ana.get('tcp_rst_count', 0)} · "
                      f"零窗口 {_ana.get('tcp_zero_window_n', 0)} · "
                      f"大包停滞流 {len(_stalls)} 条"]
            if _frag:
                _mtus = sorted({m for _, m in _frag if m})
                _lines.append(
                    f"ICMP 需分片 {len(_frag)} 个"
                    + (f" (下一跳 MTU {'/'.join(str(m) for m in _mtus)})"
                       if _mtus else " (未携带 MTU 值)"))
            if _sni:
                _shown = ", ".join(_sni[:8]) + (" 等" if len(_sni) > 8 else "")
                _lines.append(f"访问域名 (SNI/Host): {_esc_html(_shown)}"
                              + (f" · 另有 {_trunc} 个域名超出 384B 截断窗口未提取"
                                 if _trunc else ""))
            _lines.append(
                f"DNS 查询 {_ana.get('dns_query_count', 0)} 次 "
                f"(慢查询 {len(_ana.get('dns_slow_queries') or [])}) · "
                f"QUIC 包 {_ana.get('udp443_pkts', 0)} · "
                f"分析切片 {cap.get('analysis_files', 0)} 个")
            _ana_rows = ("<tr><td>证据分析</td><td colspan=3>"
                         + "<br>".join(_lines) + "</td></tr>")
        cap_panel = f"""
<div class="panel"><h3>抓包取证 (v1.8.0)</h3>
<table>
<tr><th>落盘时间</th><th>触发事件</th><th>包数</th><th>文件 (Wireshark 可直接打开)</th></tr>
{''.join(_slice_rows) if _slice_rows else "<tr><td colspan=4 class='empty'>监测期内无触发事件, 未落盘切片</td></tr>"}
{_full_html}
{_ana_rows}
<tr><td>规格</td><td colspan=3>接口 {_esc_html(str(cap.get('iface', '—')))} · 缓冲 {cap.get('ring_bytes', 0) / 1048576:.1f}/{cap.get('ring_limit_mb', 0)}MB ·
抓到 {cap.get('packets_captured', 0)} 包{f" · 超限挤出 {cap.get('dropped_old', 0)} 包" if cap.get('dropped_old') else ''} · 切片窗口 = 事件前后各 {cap.get('slice_before_s', 30)}s</td></tr>
<tr><td>隐私声明</td><td colspan=3>默认仅保存诊断所需的网络元数据: DNS 查询域名 (QNAME)、HTTP Host、TLS SNI 可能被记录 (80/443 每流首 2 包 384B 头部窗口), <b>不保存普通 TCP/HTTP 应用载荷</b>; 抓包分析当前仅覆盖 IPv4;
下次运行 NetPulse 时自动清理超过 {cap.get('retention_days', 7)} 天的切片 (最多保留 {cap.get('max_slice_files', 10)} 个)</td></tr>
</table></div>"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>NetPulse 盯障监测报告</title>
<style>
{_BRAND_HEADER_CSS}
body{{font-family:'Microsoft YaHei',sans-serif;background:#f2f5f9;margin:0;padding:24px;color:#1e293b}}
.wrap{{max-width:900px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:#64748b;font-size:13px;margin-bottom:18px}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:16px}}
.metric{{background:#fff;border-radius:10px;padding:12px 14px 10px;box-shadow:0 1px 3px rgba(0,0,0,.06);
        display:flex;flex-direction:column;gap:2px}}
.metric .lab{{font-size:11.5px;color:#64748b;line-height:1.45}}
.metric .v{{font-size:22px;font-weight:700;font-family:Consolas,monospace;line-height:1.2}}
.metric .note{{font-size:11px;color:#94a3b8;margin-top:2px;line-height:1.4}}
.banner{{background:#fff;border-left:5px solid {v_color};border-radius:8px;padding:14px 18px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.banner .verdict{{font-size:16px;font-weight:700;color:{v_color};margin-bottom:6px}}
.banner .conf{{font-size:12.5px;color:#4338ca;background:#eef2ff;display:inline-block;padding:3px 10px;border-radius:10px;margin-bottom:8px}}
.banner .text{{font-size:14px;line-height:1.7}} .banner .advice{{font-size:13px;color:#1e293b;background:#f0f9ff;border-left:3px solid #0284c7;padding:8px 12px;border-radius:0 6px 6px 0;margin-top:10px;white-space:pre-line}}
.panel{{background:#fff;border-radius:10px;padding:14px 18px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.panel h3{{margin:0 0 10px;font-size:15px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th{{text-align:left;color:#64748b;font-weight:600;border-bottom:1px solid #e2e8f0;padding:6px 8px}}
td{{border-bottom:1px solid #f1f5f9;padding:6px 8px;vertical-align:top}}
.empty{{color:#94a3b8;text-align:center;padding:16px}}
.pill{{font-size:11px;padding:2px 8px;border-radius:10px}} .pill.ok{{background:#ecfdf5;color:#0e8a4f}} .pill.open{{background:#fef2f2;color:#b42318}}
canvas{{max-width:100%}}
.note-line{{font-size:12px;color:#94a3b8}}
.footer{{color:#94a3b8;font-size:12px;text-align:center;margin-top:8px}}
</style></head><body><div class="wrap">
{_render_brand_header("盯障监测报告",
                        f"开始 {_esc_html(res.get('started_at', ''))} &nbsp;·&nbsp; 时长 {_esc_html(dur)} &nbsp;·&nbsp; "
                        f"本机 {_esc_html(res.get('local_ip') or '—')} &nbsp;·&nbsp; "
                        f"网关 {_esc_html(str(tg.get('gateway') or '—'))} &nbsp;·&nbsp; "
                        f"外网目标 {_esc_html(str(tg.get('external') or '—'))}")}
<div class="sub">长时间监测客观采样, 用于查找偶发掉线; 现场处理后仍异常时请保留 .csv/.json 一起带回会诊</div>
<div class="metrics">
{_metric("网关丢包率", f"{gw_pct}%", "err" if gw_pct > 10 else "warn" if gw_pct > 2 else "ok")}
{_metric("外网丢包率", f"{ext_pct}%", "err" if ext_pct > 10 else "warn" if ext_pct > 2 else "ok")}
{_metric("最长中断", f"{longest:.0f}s", "err" if longest >= 30 else "warn" if longest else "ok")}
{_metric("DNS 成功率", f"{dns_ok}%", "err" if (dns_ok or 100) < 90 else "ok", f"服务器 {tg.get('dns_server', '')}")}
{_metric("TCP 重传率", (f"{tq_rate_pct}%" if tq_rate_pct is not None else "—"),
          "err" if (tq_rate_pct or 0) >= 5 else "warn" if (tq_rate_pct or 0) >= 1 else "ok",
          "会话差分口径 (v1.7.0)")}
</div>
<div class="banner">
<div class="verdict">{_esc_html(v_name)}</div>
{conf_html}
<div class="text">{_esc_html(res.get('conclusion_text', ''))}</div>
<div class="advice">💡 处置建议: {_esc_html(res.get('advice', ''))}</div>
</div>
<div class="panel"><h3>事件明细 ({len([e for e in events if e['type'] != 'monitor_gap'])} 起)</h3>{ev_table}</div>
<div class="panel"><h3>延迟时序 (网关 / 外网, 红色区带 = 中断时段)</h3>
<canvas id="latChart" width="840" height="240"></canvas></div>
<div class="panel"><h3>连通率 (TCP 53 / DNS, 30 秒桶)</h3>
<canvas id="reachChart" width="840" height="160"></canvas></div>
<div class="panel"><h3>MTU 与传输质量 (v1.7.0 统计层)</h3>
<table>
<tr><th>项目</th><th>值</th></tr>
<tr><td>MTU 探测状态</td><td>{_esc_html(str(mtu.get('probe_status', '—')))}</td></tr>
{mtu_local_html}
{''.join(mtu_rows)}
<tr><td>会话 TCP 重传率</td><td>{_esc_html(tq_rate_html)}</td></tr>
<tr><td>重传采样</td><td>{len(tq_series)} 点 (30s 周期, 开机累计计数器差分)</td></tr>
</table>
<canvas id="retransChart" width="840" height="140"></canvas></div>
{cap_panel}
<div class="panel"><h3>监测详情</h3>
<table>
<tr><th>项目</th><th>值</th></tr>
<tr><td>采样规格</td><td>网关/外网 ping 1s × 2 路; TCP 53 / DNS 解析 5s; 路径 MTU 后台探测; TCP 重传统计 30s</td></tr>
<tr><td>探测目标</td><td>外网 {_esc_html(str(tg.get('external')))} → {_esc_html(str(tg.get('external_resolved')))} ·
DNS {_esc_html(str(tg.get('dns_server')))} / {_esc_html(str(tg.get('dns_domain')))}</td></tr>
<tr><td>样本数</td><td>网关 {stats.get('gw', {}).get('ok', 0)} 成功 / {stats.get('gw', {}).get('loss', 0)} 丢包 ·
外网 {stats.get('ext', {}).get('ok', 0)} / {stats.get('ext', {}).get('loss', 0)}</td></tr>
<tr><td>延迟分布</td><td>网关 p50 {stats.get('gw', {}).get('p50_ms', '—')}ms /
p95 {stats.get('gw', {}).get('p95_ms', '—')}ms · 外网 p50 {stats.get('ext', {}).get('p50_ms', '—')}ms /
p95 {stats.get('ext', {}).get('p95_ms', '—')}ms</td></tr>
</table>{notes_html}</div>
<div class="footer">由 NetPulse 生成 · 结论基于监测期内客观采样, 供装维与报障参考 ·
原始数据见同名 .csv / .json</div>
<script>
var DATA = {data_js};
function chart(id, datasets, bands, yLabel) {{
  var c = document.getElementById(id), ctx = c.getContext('2d');
  var W = c.width, H = c.height, padL = 44, padR = 10, padT = 10, padB = 22;
  var xmax = 0, ymax = 0;
  datasets.forEach(function(ds) {{
    ds.data.forEach(function(p) {{ if (p[0] > xmax) xmax = p[0]; if (p[1] > ymax) ymax = p[1]; }});
  }});
  if (!xmax) {{ ctx.fillStyle = '#94a3b8'; ctx.font = '13px sans-serif';
    ctx.fillText('无有效数据', W / 2 - 40, H / 2); return; }}
  ymax = Math.max(ymax * 1.15, 10);
  function X(t) {{ return padL + t / xmax * (W - padL - padR); }}
  function Y(v) {{ return H - padB - v / ymax * (H - padT - padB); }}
  (bands || []).forEach(function(b) {{
    ctx.fillStyle = 'rgba(255,59,48,0.10)';
    ctx.fillRect(X(b[0]), padT, Math.max(X(b[1]) - X(b[0]), 2), H - padT - padB);
  }});
  ctx.strokeStyle = '#e2e8f0'; ctx.fillStyle = '#94a3b8'; ctx.font = '10px sans-serif';
  for (var i = 0; i <= 4; i++) {{
    var v = ymax * i / 4, y = Y(v);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillText(Math.round(v), 6, y + 3);
  }}
  for (var i = 0; i <= 5; i++) {{
    var t = xmax * i / 5;
    ctx.fillText(Math.round(t) + 's', X(t) - 8, H - 6);
  }}
  datasets.forEach(function(ds) {{
    if (ds.data.length < 2) return;
    ctx.strokeStyle = ds.color; ctx.lineWidth = 1.4; ctx.beginPath();
    ds.data.forEach(function(p, i) {{
      i ? ctx.lineTo(X(p[0]), Y(p[1])) : ctx.moveTo(X(p[0]), Y(p[1]));
    }});
    ctx.stroke();
  }});
  var lx = padL + 8;
  datasets.forEach(function(ds) {{
    ctx.fillStyle = ds.color; ctx.fillRect(lx, 4, 10, 3);
    ctx.fillStyle = '#64748b'; ctx.fillText(ds.name, lx + 14, 9);
    lx += 14 + ctx.measureText(ds.name).width + 18;
  }});
}}
chart('latChart',
  [{{name: '网关 ping', color: '#0e8a4f', data: DATA.gw}},
   {{name: '外网 ping', color: '#0a84ff', data: DATA.ext}}],
  DATA.gw_bands.concat(DATA.ext_bands));
chart('reachChart',
  [{{name: 'TCP 53', color: '#ea580c', data: DATA.tcp_rate}},
   {{name: 'DNS', color: '#0891b2', data: DATA.dns_rate}}]);
chart('retransChart',
  [{{name: 'TCP 重传率 %', color: '#b26a00', data: DATA.retrans_rate}}]);
</script>
</div></body></html>"""


# ============================================================
# SECTION 4a: 盯障抓包层 (阶段 F · v1.8.0 PR-F1/F2)
# ============================================================
# 设计 (方案 §5): BPF 内核态先滤一层 → prn 回调只做「剥 payload + 入队」
# (零解析零格式化, 重传/SNI 分析全部后置到 PcapAnalyzer) → 字节记账环形
# buffer → 事件触发切片落盘 (标准 pcap, Wireshark 可直接开)。
# 隐私语义: 保护手段是「不存 payload」(80/443/8080 每流每方向前 2 包保留
# 头 + 384B 以提取 Host/SNI, 其余一律截到传输层头), 不是「少抓协议」。

# BPF: `ip and (...)` 显式排除 IPv6 (裸 `tcp` 在 libpcap 语义下同时匹配
# v4/v6; 本期分析器只处理 v4)。tcp 已涵盖 tcp/53; udp 443 = QUIC 头部计数。
CAPTURE_BPF_FILTER = "ip and (icmp or udp port 53 or tcp or udp port 443)"
CAPTURE_PAYLOAD_KEEP = 384     # 80/443/8080 前 2 包保留的 payload 字节数
CAPTURE_FIRST_PKTS = 2         # 每流每方向保留 payload 的包数 (提 Host/SNI)
CAPTURE_DEFAULT_MB = 64        # ring buffer 上限 (MB)
CAPTURE_SLICE_BEFORE_S = 30    # 事件切片: 事件开始前保留秒数
CAPTURE_SLICE_AFTER_S = 30     # 事件切片: 事件结束后保留秒数
CAPTURE_TRIGGER_TYPES = ("outage", "jitter_burst", "tcp_fail",
                         "tcp_retrans_burst")
# mtu_mismatch 是持续态不是时刻事件, 不触发切片 (只在报告建议里引导)
CAPTURE_RETENTION_DAYS = 7     # 切片保留天数 (下次运行时清理)
CAPTURE_MAX_FILES = 10         # 切片最大个数 (超删最旧)
CAPTURE_WEB_PORTS = (80, 443, 8080)


def _captures_dir():
    """抓包切片目录: <reports>/captures/ (与日期报告目录同根)。"""
    return os.path.join(os.path.dirname(_report_dir()), "captures")


def _cap_relpath(path, report_dir):
    """切片相对报告目录的链接路径; 跨盘符 (C:↔D:) 时 relpath 抛
    ValueError, 用文件名兜底 (报告与 captures 生产上同根, 仅测试会跨盘)。"""
    try:
        return os.path.relpath(path, report_dir).replace("\\", "/")
    except ValueError:
        return os.path.basename(path)


def _capture_ack_path():
    """抓包首次确认标记: 与切片同目录 (reports/captures/.capture_ack)。"""
    return os.path.join(_captures_dir(), ".capture_ack")


def _capture_confirm_once(input_fn=None):
    """首次 --capture 的隐私确认 (方案 §8.5): 只问一次, 确认后落标记文件。

    非交互环境 (无 TTY) 不阻塞 — --capture 本身已是显式授权, 直接放行并落
    标记。返回 True=继续抓包; False=用户拒绝 (降级为仅统计层)。"""
    input_fn = input_fn or input
    ack = _capture_ack_path()
    try:
        if os.path.exists(ack):
            return True
    except OSError:
        return True                    # 检查失败不拦路
    print(_c("\n  ⚠ 抓包取证首次使用确认", C_YELLOW))
    for line in (
            "     · 只保留诊断所需的网络元数据: 80/443 每条连接的前 2 个包多留 384 字节 (提取访问的域名用)",
            "     · 不保存普通 TCP/HTTP 应用载荷 (账号、密码、聊天或页面内容不落盘)",
            "     · DNS 查询域名与访问域名 (QNAME/Host/SNI) 会出现在报告里 (定位故障必需)",
            "     · 抓包分析当前仅覆盖 IPv4",
            f"     · 切片超过 {CAPTURE_RETENTION_DAYS} 天或 {CAPTURE_MAX_FILES} 个, 下次运行 NetPulse 时自动清理",
            "     · 文件在本机 reports/captures/ 下, 可随时手动删除",
    ):
        print(_c(line, C_GRAY))
    if not sys.stdin.isatty():
        print(_c("  (非交互环境, 视为已确认 — --capture 即显式授权)", C_GRAY))
        _write_capture_ack(ack)
        return True
    try:
        ans = input_fn("  确认开启抓包取证? [y/N]: ").strip().lower()
    except (EOFError, OSError):
        return True                    # 输入流异常 (管道/重定向): 不拦显式授权
    if ans in ("y", "yes"):
        _write_capture_ack(ack)
        return True
    return False


def _write_capture_ack(ack):
    try:
        os.makedirs(os.path.dirname(ack), exist_ok=True)
        with open(ack, "w", encoding="utf-8") as f:
            f.write(datetime.now().isoformat())
    except OSError:
        pass                           # 标记写不进 (只读目录): 下次再问一次


def _prompt_for_capture(input_fn=None, resume_tail=None):
    """盯障前的抓包取证询问 (v1.9.6 菜单入口, 设计稿 §4 图 A/B)。

    装维不加参数原则: --capture 的菜单入口。先跑 precheck 亮状态 —
    可用 → 出 y/f/s 选择 (Enter=不开启, 与 CLI 默认关闭一致);
    不可用 → 只显客户语言原因 + 回车继续, 不出「选了也白选」的选择题。

    v1.9.7 PR-3: 不可用若仅因缺管理员权限 (Npcap 已就绪), 先出
    「以管理员身份重启并继续盯障」一键提议 — resume_tail 是重启后接续
    盯障的 CLI 参数 (如 ["--monitor", "10"]), 提权成功 → sys.exit(0)。

    返回 (capture_mode, capture_mb): mode 为 None / "slice" / "full"。
    非 TTY (脚本/管道) 直接返回 (None, 默认), 不打断 — 与 _capture_confirm_once
    的非交互语义一致。
    """
    if not sys.stdin.isatty():
        return None, CAPTURE_DEFAULT_MB
    input_fn = input_fn or input
    print(_c("  ── 抓包取证（可选）──────────────────────────", C_GRAY))
    cap = _PcapCaptureSession("slice", CAPTURE_DEFAULT_MB)
    if not cap.precheck():
        print(_c(f"  ✘ 抓包暂不可用: {cap.unavailable_reason}", C_YELLOW))
        # v1.9.7 PR-3: 只缺管理员权限时, 别让用户手动关闭重开 — 一键提权接续
        if not _is_admin() and _npcap_installed():
            _offer_elevation_relaunch(
                resume_tail, reason="抓包取证需要管理员权限 (Npcap 已就绪)")
        print(_c("     本次仅统计层盯障 (掉线/抖动统计不受影响)。", C_GRAY))
        try:
            input_fn(_c("  按 Enter 继续...", C_GRAY))
        except (EOFError, KeyboardInterrupt):
            pass
        return None, CAPTURE_DEFAULT_MB
    print(_c("  ✔ 抓包条件满足: Npcap · 管理员权限 · 抓包接口已就绪", C_GREEN))
    print(_c("     掉线/抖动发生时自动保存前后 30 秒原始报文 (.pcap),", C_GRAY))
    print(_c("     Wireshark 可直接打开; 仅保留包头与域名, 不存账号密码。", C_GRAY))
    try:
        ans = input_fn(_c("  开启抓包取证? [Enter=不开启 / y=事件切片 / "
                          "f=全程 / s=切片+改上限]: ", C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None, CAPTURE_DEFAULT_MB
    if ans in ("", "n", "no"):
        return None, CAPTURE_DEFAULT_MB
    if ans.startswith("f"):
        return "full", CAPTURE_DEFAULT_MB
    if ans.startswith("s"):
        try:
            mb_s = input_fn(_c("  抓包缓冲上限 MB (默认 64, 最小 8): ",
                               C_GREEN)).strip()
            mb = int(mb_s) if mb_s else CAPTURE_DEFAULT_MB
        except (EOFError, KeyboardInterrupt, ValueError):
            mb = CAPTURE_DEFAULT_MB    # 输入非法 (非数字/中断): 用默认, 不拦盯障
        return "slice", max(8, mb)
    return "slice", CAPTURE_DEFAULT_MB   # y / yes / 其他 → 事件切片


def _cleanup_old_captures(cap_dir=None):
    """启动时清理切片: 超过 CAPTURE_RETENTION_DAYS 天或总数超 CAPTURE_MAX_FILES
    (删最旧)。返回删除的文件数; 失败静默 (清理不是主路径)。"""
    cap_dir = cap_dir or _captures_dir()
    try:
        files = [os.path.join(cap_dir, f) for f in os.listdir(cap_dir)
                 if f.endswith(".pcap")]
        removed = 0
        now = time.time()
        for p in files:
            try:
                if now - os.path.getmtime(p) > CAPTURE_RETENTION_DAYS * 86400:
                    os.remove(p)
                    removed += 1
            except OSError:
                pass
        files = [p for p in files if os.path.exists(p)]
        if len(files) > CAPTURE_MAX_FILES:
            files.sort(key=os.path.getmtime)
            for p in files[:len(files) - CAPTURE_MAX_FILES]:
                try:
                    os.remove(p)
                    removed += 1
                except OSError:
                    pass
        return removed
    except OSError:
        return 0


class _PcapRingBuffer:
    """按字节记账的滚动 buffer (方案 §5.3): deque 只存引用, _bytes 累计
    len(bytes(pkt))。v1 方案的 deque(maxlen=N) 数的是包不是字节 — 同样
    条数下字节数差 3 个数量级, 会把 64MB 预算用成几十 GB。"""

    def __init__(self, limit_bytes):
        self.limit_bytes = limit_bytes
        self._q = deque()
        self._bytes = 0
        self.dropped = 0        # 因超限被挤出的包数 (报告如实展示)

    def push(self, pkt):
        n = len(bytes(pkt))
        self._q.append((pkt, n))
        self._bytes += n
        while self._bytes > self.limit_bytes and len(self._q) > 1:
            self._bytes -= self._q.popleft()[1]
            self.dropped += 1

    def slice_window(self, t0, t1):
        """按包时间戳取 [t0, t1] 窗口 (事件切片)。"""
        return [p for p, _ in self._q if t0 <= float(p.time) <= t1]

    def packets(self):
        return [p for p, _ in self._q]

    def __len__(self):
        return len(self._q)

    @property
    def cur_bytes(self):
        return self._bytes


def _capture_default_iface():
    """默认路由出口接口名。scapy 2.7 的 route() 返回 (iface, gw, dst) —
    取 [2] 会拿到网关 IP 当接口名, 嗅探线程静默死掉一颗包都抓不到 (实机
    踩过)。route[0] 不在接口清单里时回退 conf.iface; 全失败返回 None。"""
    _ensure_scapy()
    try:
        ifc = conf.route.route("0.0.0.0")[0]
        if ifc and ifc in (get_if_list() or []):
            return ifc
    except Exception:
        pass
    try:
        return str(conf.iface) or None
    except Exception:
        return None


def _patch_ip_lengths(buf, ip_off, ihl, l4_off, proto):
    """就地修正截断包的 L3/L4 长度字段 + 重算 IPv4 头校验和 (v1.9.9)。

    buf: bytearray, 截断后的完整以太帧字节。
    修复点:
      - IP Total Length = len(buf) - ip_off (以太/VLAN 头之外的长度)
      - UDP 截断 (QUIC): UDP length = len(buf) - l4_off, checksum 置 0
        (载荷已剥, RFC 768 0 = 未计算, 避免残留伪校验和误导 Wireshark)
      - IPv4 头校验和: 原 checksum 先清零再 16-bit 反码累加取反
        (长度字段变了, 原校验和必然失效)
    不修 TCP checksum (载荷剥除后必不符, Wireshark 默认不校验 TCP CS)。
    调用方保证 ihl/l4_off 由同一 buf 解析 (纯头算术, 不触 scapy 字段)。
    """
    ip_total = len(buf) - ip_off
    buf[ip_off + 2] = (ip_total >> 8) & 0xFF
    buf[ip_off + 3] = ip_total & 0xFF
    if proto == 17:                                # UDP 截断 (QUIC 443)
        udp_len = len(buf) - l4_off
        buf[l4_off + 4] = (udp_len >> 8) & 0xFF
        buf[l4_off + 5] = udp_len & 0xFF
        buf[l4_off + 6] = 0
        buf[l4_off + 7] = 0
    buf[ip_off + 10] = 0
    buf[ip_off + 11] = 0
    csum = 0
    for i in range(ip_off, ip_off + ihl, 2):
        csum += (buf[i] << 8) | buf[i + 1]
    while csum >> 16:
        csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (~csum) & 0xFFFF
    buf[ip_off + 10] = (csum >> 8) & 0xFF
    buf[ip_off + 11] = csum & 0xFF


def _capture_strip_packet(pkt, flow_state):
    """剥 payload (PR-F1): 返回可入 ring 的包 (截断后重建, 保留原时间戳)。

    - ICMP / UDP 53 (DNS): 整包 (小, 分析需要)
    - UDP 443 (QUIC): 头 + 16B (仅计数/速率, 不解析)
    - TCP 80/443/8080: 每流**每方向**前 CAPTURE_FIRST_PKTS 包保留头 +
      CAPTURE_PAYLOAD_KEEP (提 Host/SNI); 之后截到 TCP 头
    - 其他 TCP: 截到 TCP 头 (重传/dup-ack/zero-window 判定只需 seq/ack/win/flags)

    flow_state: dict[(sport, dport)] -> 已见包数。key 含方向 (src→dst 的
    (sport,dport) 与反方向 (dport,sport) 是两个 key), O(1)。
    只做头长算术, 不触 scapy 字段访问 (prn 零工作原则)。
    v1.9.9: 截断后同步改写 IP Total Length / UDP length 并重算 IPv4 校验和,
    保证落盘 pcap 在 Wireshark 里不产生「长度虚高」类专家误报。
    """
    _ensure_scapy()
    if not isinstance(pkt, Ether):
        return pkt                     # 非 Ethernet 链路 (loopback 等): 原样保留
    raw = bytes(pkt)
    if len(raw) < 34:                  # Ether + 最小 IP 头都不够
        return pkt
    ethertype = (raw[12] << 8) | raw[13]
    ip_off = 14
    if ethertype == 0x8100:            # 单层 VLAN tag
        if len(raw) < 38:
            return pkt
        ethertype = (raw[16] << 8) | raw[17]
        ip_off = 18
    if ethertype != 0x0800:            # 非 IPv4 (BPF 已滤, 防御)
        return pkt
    ihl = (raw[ip_off] & 0x0F) * 4
    if ihl < 20 or len(raw) < ip_off + ihl:
        return pkt
    proto = raw[ip_off + 9]
    l4_off = ip_off + ihl

    if proto == 1:                     # ICMP: 整包
        return pkt
    if proto == 17:                    # UDP
        if len(raw) < l4_off + 8:
            return pkt
        sport = (raw[l4_off] << 8) | raw[l4_off + 1]
        dport = (raw[l4_off + 2] << 8) | raw[l4_off + 3]
        if sport == 53 or dport == 53:
            return pkt                 # DNS: 整包
        if sport == 443 or dport == 443:
            keep = l4_off + 8 + 16     # QUIC: 头 + 16B
        else:
            return pkt
    elif proto == 6:                   # TCP
        if len(raw) < l4_off + 20:
            return pkt
        thl = ((raw[l4_off + 12] >> 4) & 0x0F) * 4
        sport = (raw[l4_off] << 8) | raw[l4_off + 1]
        dport = (raw[l4_off + 2] << 8) | raw[l4_off + 3]
        hdr_end = l4_off + thl
        if sport in CAPTURE_WEB_PORTS or dport in CAPTURE_WEB_PORTS:
            key = (sport, dport)
            n = flow_state.get(key, 0)
            flow_state[key] = n + 1
            if n < CAPTURE_FIRST_PKTS:
                keep = hdr_end + CAPTURE_PAYLOAD_KEEP
            else:
                keep = hdr_end
        else:
            keep = hdr_end
    else:
        return pkt                     # 其他协议 (BPF 已滤, 防御)

    if keep >= len(raw):
        return pkt
    # v1.9.9 (抓包复核 P0): 截断重建后必须同步修正 L3/L4 长度字段, 否则
    # Wireshark 按「IP 头总长 − 实际字节数」推算每段负载 → 序列空间不连续,
    # 对成百上千个被截断的包误报 "TCP ACKed lost segment" / "Dup ACK" 等
    # 专家提示 (实测旧 pcap 61.8% 的包 IP.len 虚高)。
    # 纯字节操作, 延续本函数「不触 scapy 字段访问」的零工作原则。
    buf = bytearray(raw[:keep])
    _patch_ip_lengths(buf, ip_off, ihl, l4_off, proto)
    trimmed = Ether(bytes(buf))
    trimmed.time = pkt.time            # 截断重建会丢时间戳, 手工带回
    return trimmed


class _PcapCaptureSession:
    """盯障抓包会话 (PR-F1/F2)。检查链任一失败 → available=False 并给出
    客户语言提示, 统计层照跑、退出码不变 (方案 §5.4)。

    mode: "slice" (事件触发切片, 默认) / "full" (全程落一个 pcap)。
    full 模式同样受 --capture-mb 字节上限约束 (超限挤最旧, 报告如实展示
    dropped 数) — 无上限的「全程」在一台高流量机器上就是磁盘打爆。
    """

    def __init__(self, mode="slice", max_mb=CAPTURE_DEFAULT_MB):
        self.mode = mode
        self.max_mb = max(8, int(max_mb))
        self.available = False
        self.unavailable_reason = ""
        self.iface = None
        self._sniffer = None
        self.ring = None
        self.pkt_count = 0
        self.dropped = 0
        self.slices = []           # [{"event_id", "event_type", "ts", "path", "pkts"}]
        self.full_pcap = None
        self._flow_state = {}
        self._lock = threading.Lock()
        self._seen_events = set()  # {(type, stream, start_ts)}
        self._pending = []         # [{"due", "ev"}] 待落盘切片
        self._start_stamp = None

    # ── 检查链: --no-scapy → scapy/Npcap → 管理员 → 出口接口 ──
    def precheck(self):
        _ensure_scapy()
        if FORCE_NO_SCAPY or not SCAPY_AVAILABLE:
            self.unavailable_reason = ("scapy 被禁用 (--no-scapy 或未安装 scapy), "
                                       "抓包不可用 — 统计层不受影响")
            return False
        if not _npcap_installed():
            self.unavailable_reason = ("未检测到 Npcap (抓包驱动)。安装: "
                                       "https://npcap.com 勾选 WinPcap API 兼容模式, "
                                       "或 netpulse --install; 统计层不受影响")
            return False
        if not _is_admin():
            self.unavailable_reason = ("Npcap 默认只允许管理员抓包 — 请以管理员身份"
                                       "重跑 (统计层不受影响)")
            return False
        try:
            # 默认路由出口接口 (iface 在 route 3 元组第 0 位, 校验在接口清单内)
            _iface = _capture_default_iface()
            if not _iface:
                raise ValueError("默认路由接口解析为空")
            self.iface = _iface
        except Exception as e:
            self.unavailable_reason = f"解析默认路由接口失败 ({e}); 统计层不受影响"
            return False
        self.available = True
        return True

    def start(self):
        if not self.available:
            return False
        from scapy.all import AsyncSniffer
        self.ring = _PcapRingBuffer(self.max_mb * 1024 * 1024)
        self._start_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        _cleanup_old_captures()

        def _prn(pkt):
            # 零工作原则: 只截断 + 入队; 任何异常都不让 sniffer 线程死掉
            try:
                kept = _capture_strip_packet(pkt, self._flow_state)
                with self._lock:
                    self.ring.push(kept)
                    self.pkt_count += 1
            except Exception:
                pass

        self._sniffer = AsyncSniffer(iface=self.iface,
                                     filter=CAPTURE_BPF_FILTER,
                                     prn=_prn, store=False)
        self._sniffer.start()
        # 接口/驱动层错误只在嗅探线程内抛 (主线程看不到) — 静默死亡会让
        # 「已启动」后面跟 0 包。等 1s 验活, 死了按启动失败降级。
        time.sleep(1.0)
        _thr = getattr(self._sniffer, "thread", None)
        if _thr is not None and not _thr.is_alive():
            self.stop()
            self.unavailable_reason = ("抓包线程启动后立即退出 (接口或驱动异常), "
                                       "已降级为仅统计层")
            return False
        return True

    def stop(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        with self._lock:
            self.dropped = self.ring.dropped if self.ring else 0

    # ── 事件触发切片 (PR-F2): 由 run_monitor_mode 的循环周期调用 ──
    def poll_events(self, session, now=None):
        """增量事件检测 (滚动口径): 检测到新的触发型事件 → 排定「事件结束
        +30s」落盘。检测是后置的 (事件在快照里成型才看得见), 只能切已过去
        的窗口, 恰好落在 ring 保留范围内。"""
        if not self.available or self.mode != "slice":
            return
        now = now or time.time()
        snap = session.snapshot()
        # 补上会话差分口径, 让 tcp_retrans_burst 在增量检测里也可见
        # (mtu_mismatch 是持续态, 不在触发集, 无需补 mtu 块)
        snap["tcp_quality"] = session._tcpstat_quality()
        for ev in _detect_monitor_events(snap, session._t0, now):
            if ev["type"] not in CAPTURE_TRIGGER_TYPES:
                continue
            key = (ev["type"], ev.get("stream", ""), ev["start_ts"])
            if key in self._seen_events:
                continue
            self._seen_events.add(key)
            self._pending.append(
                {"due": ev["end_ts"] + CAPTURE_SLICE_AFTER_S, "ev": dict(ev)})
        self._flush_due_slices(now)

    def _flush_due_slices(self, now, final=False):
        remain = []
        for ps in self._pending:
            if not final and now < ps["due"]:
                remain.append(ps)
                continue
            ev = ps["ev"]
            t0 = ev["start_ts"] - CAPTURE_SLICE_BEFORE_S
            t1 = min(ev["end_ts"] + CAPTURE_SLICE_AFTER_S, now)
            pkts = self.ring.slice_window(t0, t1) if self.ring else []
            if pkts:
                path = self._write_pcap(
                    pkts, f"{self._start_stamp}_slice_{ev['type']}")
                if path:
                    self.slices.append({
                        "event_type": ev["type"], "event_stream": ev.get("stream", ""),
                        "event_start": round(ev["start_ts"] - 0, 3),
                        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "path": os.path.basename(path), "pkts": len(pkts),
                        "rel": _cap_relpath(path, _report_dir())})
        self._pending = remain

    def _write_pcap(self, pkts, stem):
        try:
            from scapy.all import wrpcap
            cap_dir = _captures_dir()
            os.makedirs(cap_dir, exist_ok=True)
            path = os.path.join(cap_dir, f"monitor_{stem}.pcap")
            # 同一事件类型多次触发 (如多段抖动): start_ts 区分, 不覆盖
            if os.path.exists(path):
                path = path.replace(".pcap", f"_{int(time.time())}.pcap")
            wrpcap(path, pkts)
            return path
        except Exception:
            return None

    def finish(self, result):
        """会话收尾: 冲洗未到期切片 / full 模式整体落盘; 给权威事件挂切片
        相对链接; 返回可序列化的 capture 摘要块 (挂 result["capture"])。"""
        if not self.available:
            return None
        self._flush_due_slices(time.time(), final=True)
        if self.mode == "full" and self.ring and len(self.ring):
            path = self._write_pcap(self.ring.packets(),
                                    f"{self._start_stamp}_full")
            self.full_pcap = os.path.basename(path) if path else None
        # 权威事件 (build_result 已编 id) ← 切片匹配: (type, stream, start_ts)
        slice_index = {(s["event_type"], s["event_stream"],
                        round(s["event_start"], 3)): s for s in self.slices}
        report_dir = _report_dir()
        for ev in result.get("events", []):
            key = (ev.get("type", ""), ev.get("stream", ""),
                   round(ev.get("start_ts", 0), 3))
            s = slice_index.get(key)
            if not s:
                continue
            cap_path = os.path.join(_captures_dir(), s["path"])
            ev["pcap_slice"] = _cap_relpath(cap_path, report_dir)
        return {
            "mode": self.mode,
            "available": True,
            "iface": self.iface,
            "filter": CAPTURE_BPF_FILTER,
            "packets_captured": self.pkt_count,
            "ring_bytes": self.ring.cur_bytes if self.ring else 0,
            "ring_limit_mb": self.max_mb,
            "dropped_old": self.dropped,
            "slice_before_s": CAPTURE_SLICE_BEFORE_S,
            "slice_after_s": CAPTURE_SLICE_AFTER_S,
            "retention_days": CAPTURE_RETENTION_DAYS,
            "max_slice_files": CAPTURE_MAX_FILES,
            "slices": self.slices,
            "full_pcap": self.full_pcap,
            "full_pcap_rel": (_cap_relpath(
                os.path.join(_captures_dir(), self.full_pcap), report_dir)
                if self.full_pcap else None),
        }


# ============================================================
# SECTION 4b: 抓包证据分析 (PR-F3) — PcapAnalyzer
# 离线分析切片 pcap → 结构化结论。只依赖头部字段 + 首 2 包 384B,
# 不依赖应用层内容 (隐私红线)。scapy 缺失时不可用 (调用方需降级)。
# ============================================================

@dataclass
class CaptureDiagnostic:
    """抓包切片分析结论; to_dict() 后可整体 JSON 序列化。"""
    icmp_count: int = 0
    # [(ts, next_hop_mtu)] — PMTUD 信号 A (ICMP 3/4) 的直接证据
    icmp_frag_needed: list = field(default_factory=list)
    # 每方向一条流摘要 (见 PcapAnalyzer._flow_state 的键)
    streams: list = field(default_factory=list)
    tcp_retransmit_count: int = 0
    tcp_dup_ack_count: int = 0
    tcp_rst_count: int = 0
    tcp_zero_window_n: int = 0
    dns_query_count: int = 0
    dns_slow_queries: list = field(default_factory=list)  # [(q_ts, r_ts, name)]
    http_hosts: list = field(default_factory=list)
    tls_sni: list = field(default_factory=list)           # 含 "sni_truncated" 占位
    udp443_pkts: int = 0
    retrans_rate: float = 0.0
    suspected_pmtud_blackhole: bool = False
    suspected_tcp_loss_burst: bool = False
    suspected_dns_slow: bool = False

    def to_dict(self):
        return {
            "icmp_count": self.icmp_count,
            "icmp_frag_needed": [list(t) for t in self.icmp_frag_needed],
            "streams": self.streams,
            "tcp_retransmit_count": self.tcp_retransmit_count,
            "tcp_dup_ack_count": self.tcp_dup_ack_count,
            "tcp_rst_count": self.tcp_rst_count,
            "tcp_zero_window_n": self.tcp_zero_window_n,
            "dns_query_count": self.dns_query_count,
            "dns_slow_queries": [list(t) for t in self.dns_slow_queries],
            "http_hosts": self.http_hosts,
            "tls_sni": self.tls_sni,
            "udp443_pkts": self.udp443_pkts,
            "retrans_rate": self.retrans_rate,
            "suspected_pmtud_blackhole": self.suspected_pmtud_blackhole,
            "suspected_tcp_loss_burst": self.suspected_tcp_loss_burst,
            "suspected_dns_slow": self.suspected_dns_slow,
        }


class PcapAnalyzer:
    """三信号 PMTUD 判定 + 轻量流重组 (方案 §6.1/§6.3)。

    - 信号 A: ICMP type3/code4 (frag-needed, 含 next-hop MTU);
    - 信号 B: 握手成功 (双向 MSS≥1400) + full-size 段同 seq 停滞 (≥3 次)
      且小包仍在流动;
    - 信号 C: SYN MSS > path_mtu - 40 (path_mtu 来自 F0 统计层, 可缺省)。
    判定: A 或 (B∧C) → suspected_pmtud_blackhole; 仅 B → tcp_loss 候选。
    MSS<1460 本身不是判据 (PPPoE 正常 1452)。
    """

    DNS_SLOW_S = 1.0          # query→resp 超过该值记慢查询
    RETRANS_GAP_S = 1.0       # 同 seq 间隔超此值视为新一轮首传 (慢速场景)
    DUP_ACK_MIN = 3           # 连续重复 ack ≥3 才记 dup ack
    FULLSIZE_BYTES = 1200     # payload 超此值算 full-size 段 (PMTUD 嫌疑段)
    STALL_SEEN_MIN = 3        # 同 (seq,len) 出现 ≥3 次 (含首传) 判停滞
    MSS_HANDSHAKE_MIN = 1400  # 握手 MSS 下限 — 低于此可能是隧道/PPPoE 正常小 MSS
    MSS_OVER_PATH = 40        # 信号 C 裕量: IP+TCP 头
    LOSS_RATE = 0.08          # 重传占比阈值 (拥塞丢包)
    LOSS_MIN_SEGS = 50        # 样本不足不判 loss (防小样本误报)

    _HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                    b"OPTIONS ", b"PATCH ", b"HTTP/1.")

    def __init__(self, path_mtu=None):
        self.path_mtu = path_mtu

    # ---- 对外入口 --------------------------------------------------
    def analyze(self, src) -> CaptureDiagnostic:
        """src: scapy 包列表, 或 pcap 文件路径 (rdpcap 读取)。"""
        _ensure_scapy()
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy 不可用, 无法分析抓包")
        pkts = src
        if isinstance(src, str):
            from scapy.all import rdpcap
            pkts = rdpcap(src)
        d = CaptureDiagnostic()
        flows = {}
        dns_pending = {}          # (client_port, dns_id) -> (q_ts, name)
        small_ack_n = 0           # 全局纯 ACK/keepalive 包数 (小包仍在流动)
        data_seg_n = 0
        for pkt in pkts:
            try:
                ts = float(pkt.time)
            except Exception:
                ts = 0.0
            ip = pkt.getlayer(IP)
            if ip is None:
                continue
            l4 = ip.payload          # 只看外层 L4 — ICMP 引用的原包不算流
            if isinstance(l4, TCP):
                key = (ip.src, l4.sport, ip.dst, l4.dport)
                st = self._flow_state(flows, key)
                fl = str(l4.flags)
                mss = self._tcp_mss(l4)
                if fl == "S":
                    st["syn_n"] += 1
                    if st["syn_mss"] is None and mss:
                        st["syn_mss"] = mss
                elif fl == "SA":
                    st["synack_seen"] = True
                    if st["synack_mss"] is None and mss:
                        st["synack_mss"] = mss
                if "R" in fl:
                    st["rst_n"] += 1
                if l4.window == 0 and "S" not in fl:
                    st["zero_win_n"] += 1
                raw = bytes(l4.payload)
                plen = len(raw)
                if plen == 0:
                    if "S" not in fl and "F" not in fl:
                        small_ack_n += 1
                        self._dup_ack(d, st, l4.ack)
                else:
                    data_seg_n += 1
                    self._data_segment(d, st, ts, l4.seq, plen)
                    self._l7_extract(d, key, raw)
            elif isinstance(l4, UDP):
                if l4.dport == 443 or l4.sport == 443:
                    d.udp443_pkts += 1
                elif l4.dport == 53 or l4.sport == 53:
                    self._dns_track(d, dns_pending, ip, l4, ts)
            elif isinstance(l4, ICMP):
                d.icmp_count += 1
                if int(l4.type) == 3 and int(l4.code) == 4:
                    mtu = self._icmp_next_hop_mtu(l4)
                    d.icmp_frag_needed.append((round(ts, 3), mtu))
        # ---- 汇总流表 ----
        for key, st in flows.items():
            rev = flows.get((key[2], key[3], key[0], key[1]))
            handshake_ok = st["synack_seen"] or bool(rev and rev["synack_mss"])
            if st["syn_n"] >= 2 and not handshake_ok:
                st["syn_retrans_n"] = st["syn_n"]   # SYN 反复无应答
            d.tcp_rst_count += st["rst_n"]
            d.tcp_zero_window_n += st["zero_win_n"]
            d.streams.append({
                "key": f"{key[0]}:{key[1]}>{key[2]}:{key[3]}",
                "syn_mss": st["syn_mss"],
                # SYN-ACK 在反方向流上 — 汇总进本条便于报告展示
                "synack_mss": st["synack_mss"]
                or ((rev or {}).get("synack_mss")),
                "syn_retrans_n": st["syn_retrans_n"],
                "rst_n": st["rst_n"], "zero_win_n": st["zero_win_n"],
                "fullsize_stall": st["fullsize_stall"],
            })
        # ---- 三信号判定 ----
        sig_a = bool(d.icmp_frag_needed)
        sig_b = self._signal_b(flows, small_ack_n)
        sig_c = self._signal_c(flows)
        d.suspected_pmtud_blackhole = sig_a or (sig_b and sig_c)
        rate = (d.tcp_retransmit_count / data_seg_n) if data_seg_n else 0.0
        d.retrans_rate = round(rate, 4)
        d.suspected_tcp_loss_burst = (
            (sig_b and not d.suspected_pmtud_blackhole)
            or (data_seg_n >= self.LOSS_MIN_SEGS and rate >= self.LOSS_RATE))
        d.suspected_dns_slow = len(d.dns_slow_queries) >= 2
        return d

    # ---- 内部工具 --------------------------------------------------
    @staticmethod
    def _flow_state(flows, key):
        st = flows.get(key)
        if st is None:
            st = {"syn_n": 0, "synack_seen": False, "syn_mss": None,
                  "synack_mss": None, "syn_retrans_n": 0, "rst_n": 0,
                  "zero_win_n": 0, "seg": {}, "last_ack": None,
                  "ack_rep": 0, "ack_flagged": False, "fullsize_stall": False}
            flows[key] = st
        return st

    @staticmethod
    def _tcp_mss(t):
        for name, val in (t.options or []):
            if name == "MSS":
                if isinstance(val, (bytes, bytearray)):
                    return int.from_bytes(val, "big")
                return int(val)
        return None

    @staticmethod
    def _dup_ack(d, st, ack):
        """连续重复 ack (无 payload) 达阈值记 1 次 dup-ack 突发。"""
        if ack == st["last_ack"]:
            st["ack_rep"] += 1
            if st["ack_rep"] >= PcapAnalyzer.DUP_ACK_MIN and not st["ack_flagged"]:
                d.tcp_dup_ack_count += 1
                st["ack_flagged"] = True
        else:
            st["last_ack"] = ack
            st["ack_rep"] = 0
            st["ack_flagged"] = False

    def _data_segment(self, d, st, ts, seq, plen):
        """重传 = 同流同方向 payload>0 且 (seq,len) 相同, 间隔 ≤1s。"""
        ent = st["seg"].get((seq, plen))
        if ent is None:
            st["seg"][(seq, plen)] = [ts, 1]
            return
        if ts - ent[0] <= self.RETRANS_GAP_S:
            ent[1] += 1
            d.tcp_retransmit_count += 1
            if plen > self.FULLSIZE_BYTES and ent[1] >= self.STALL_SEEN_MIN:
                st["fullsize_stall"] = True
        else:
            ent[1] = 1        # 间隔过久 — 视为应用层重发/新一轮首传
        ent[0] = ts

    def _l7_extract(self, d, key, raw):
        """仅限首 2 包 384B 窗口内的 Host / SNI (方案 §5.2 隐私设计)。"""
        dport = key[3]
        head = raw[:CAPTURE_PAYLOAD_KEEP] if len(raw) > CAPTURE_PAYLOAD_KEEP else raw
        if dport in CAPTURE_WEB_PORTS and head.startswith(self._HTTP_STARTS):
            m = re.search(rb"(?im)^host:\s*([^\r\n]+)", head)
            if m:
                host = m.group(1).decode("ascii", "ignore").strip()
                if host and host not in d.http_hosts:
                    d.http_hosts.append(host)
        elif dport == 443 and head[:1] == b"\x16":
            sni = self._parse_sni(head)
            if sni and sni not in d.tls_sni:
                d.tls_sni.append(sni)

    @classmethod
    def _parse_sni(cls, buf):
        """ClientHello 头部解析 SNI; 结构不完整 (截断) → "sni_truncated"。"""
        try:
            off = 5                                   # TLS record 头
            if len(buf) < off or buf[0] != 0x16:
                return None
            if buf[off] != 0x01:                      # ClientHello
                return None
            off += 4                                  # handshake 头
            off += 2 + 32                             # 版本 + random
            if off >= len(buf):
                return "sni_truncated"
            off += 1 + buf[off]                       # session_id
            if off + 2 > len(buf):
                return "sni_truncated"
            off += 2 + int.from_bytes(buf[off:off + 2], "big")   # cipher suites
            if off >= len(buf):
                return "sni_truncated"
            off += 1 + buf[off]                       # compression
            if off + 2 > len(buf):
                return "sni_truncated"
            exts_len = int.from_bytes(buf[off:off + 2], "big")
            off += 2
            end = min(off + exts_len, len(buf))
            while off + 4 <= end:
                etype = int.from_bytes(buf[off:off + 2], "big")
                elen = int.from_bytes(buf[off + 2:off + 4], "big")
                off += 4
                if off + elen > len(buf):
                    return "sni_truncated"
                if etype == 0x0000:                   # server_name
                    p = off + 2                       # 跳过 list 长度
                    if p + 3 > len(buf):
                        return "sni_truncated"
                    if buf[p] == 0x00:                # host_name
                        p += 1
                        nl = int.from_bytes(buf[p:p + 2], "big")
                        p += 2
                        if p + nl > len(buf):
                            return "sni_truncated"
                        return buf[p:p + nl].decode("ascii", "ignore")
                    return None
                off += elen
            return None
        except Exception:
            return None

    @staticmethod
    def _dns_track(d, pending, ip, u, ts):
        _ensure_scapy()
        dns = u.payload
        if not isinstance(dns, DNS):
            return
        try:
            qid = int(dns.id)
            if u.dport == 53:                         # 查询
                name = ""
                if dns.qd is not None:
                    qn = dns.qd.qname
                    name = (qn.decode("ascii", "ignore")
                            if isinstance(qn, (bytes, bytearray)) else str(qn))
                    name = name.rstrip(".")
                d.dns_query_count += 1
                pending[(u.sport, qid)] = (ts, name)
            else:                                     # 响应
                ent = pending.pop((u.dport, qid), None)
                if ent and ts - ent[0] > PcapAnalyzer.DNS_SLOW_S:
                    d.dns_slow_queries.append(
                        (round(ent[0], 3), round(ts, 3), ent[1]))
        except Exception:
            pass

    @staticmethod
    def _icmp_next_hop_mtu(ic):
        """nexthopmtu 在 ICMP 头 4B 保留字段的低 2B (偏移 6..8)。
        真实抓包 (dissect) 直接给 nexthopmtu 字段; 合成/未 build 的包
        只能读 unused 原始字节 (bytes() 重建会把 unused 抹成 nexthopmtu=0)。"""
        try:
            mtu = int(getattr(ic, "nexthopmtu", 0) or 0)
            if mtu:
                return mtu
            unused = getattr(ic, "unused", None)
            if isinstance(unused, (bytes, bytearray)) and len(unused) >= 4:
                return int.from_bytes(unused[2:4], "big")
            return 0
        except Exception:
            return 0

    def _signal_b(self, flows, small_ack_n):
        """行为签名: 停滞流握手正常 (双向 MSS≥1400) 且小包仍在流动。"""
        if small_ack_n < 3:
            return False
        for key, st in flows.items():
            if not st["fullsize_stall"]:
                continue
            rev = flows.get((key[2], key[3], key[0], key[1]))
            synack_mss = (rev or {}).get("synack_mss")
            if ((st["syn_mss"] or 0) >= self.MSS_HANDSHAKE_MIN
                    and (synack_mss or 0) >= self.MSS_HANDSHAKE_MIN):
                return True
        return False

    def _signal_c(self, flows):
        """SYN MSS 超过 path_mtu-40 (需 F0 统计层提供 path_mtu)。"""
        if not self.path_mtu:
            return False
        limit = self.path_mtu - self.MSS_OVER_PATH
        return any(st["syn_mss"] and st["syn_mss"] > limit
                   for st in flows.values())


def _merge_capture_diag(dst: CaptureDiagnostic, src: CaptureDiagnostic):
    """多切片诊断合并 (计数累加 / 疑点取或 / 域名去重 / 重传率取最差)。"""
    dst.icmp_count += src.icmp_count
    dst.icmp_frag_needed += src.icmp_frag_needed
    dst.tcp_retransmit_count += src.tcp_retransmit_count
    dst.tcp_dup_ack_count += src.tcp_dup_ack_count
    dst.tcp_rst_count += src.tcp_rst_count
    dst.tcp_zero_window_n += src.tcp_zero_window_n
    dst.dns_query_count += src.dns_query_count
    dst.dns_slow_queries += src.dns_slow_queries
    dst.udp443_pkts += src.udp443_pkts
    for h in src.http_hosts:
        if h not in dst.http_hosts:
            dst.http_hosts.append(h)
    for s in src.tls_sni:
        if s not in dst.tls_sni:
            dst.tls_sni.append(s)
    dst.streams += src.streams
    dst.retrans_rate = max(dst.retrans_rate, src.retrans_rate)
    dst.suspected_pmtud_blackhole |= src.suspected_pmtud_blackhole
    dst.suspected_tcp_loss_burst |= src.suspected_tcp_loss_burst
    dst.suspected_dns_slow |= src.suspected_dns_slow


def _apply_capture_evidence(result):
    """PR-F4 (方案 §7.2): 抓包证据联动盯障结论 — finish() 之后调用。

    - 对切片 (与全程 pcap) 离线跑 PcapAnalyzer; 信号 C 用统计层最小有效 path_mtu;
    - suspected_* → 结论/建议追加 + verdict 升级 (stable→degraded) + 对应事件
      根因标注 (报告里显示 "🔬 抓包佐证" 徽标);
    - 置信度: 黑洞确认 92% / 其他佐证 85% — 无抓包证据时不出该字段;
    - 抓包永远不是判定的前置条件: 本函数只追加佐证, 不推翻统计层结论。
    单个切片分析失败跳过; 全部失败时不改 result 任何字段。"""
    cap = result.get("capture") or {}
    names = [s.get("path") or "" for s in (cap.get("slices") or [])]
    if cap.get("full_pcap"):
        names.append(cap["full_pcap"])
    names = [n for n in names if n]
    if not names:
        return
    # 信号 C 输入: 统计层 path_mtu 取最小有效值 (最受限通道)
    path_mtu = None
    for r in (result.get("mtu") or {}).get("path_mtus") or []:
        v = r.get("path_mtu")
        if v and not r.get("error") and (path_mtu is None or v < path_mtu):
            path_mtu = v
    cap_dir = _captures_dir()
    merged = CaptureDiagnostic()
    analyzed = 0
    for name in names:
        p = os.path.join(cap_dir, name)
        if not os.path.exists(p):
            continue
        try:
            _merge_capture_diag(
                merged, PcapAnalyzer(path_mtu=path_mtu).analyze(p))
            analyzed += 1
        except Exception:
            continue
    if not analyzed:
        return
    cap["analysis"] = merged.to_dict()
    cap["analysis_files"] = analyzed

    events = result.get("events", [])

    def _tag(evs, note):
        for ev in evs:
            ev["pcap_evidence"] = note
            base = ev.get("root_cause", "")
            if "抓包" not in base:
                ev["root_cause"] = (base + "；" if base else "") \
                    + f"抓包佐证: {note}"

    text_bits, advice_bits, summary_bits = [], [], []
    if merged.suspected_pmtud_blackhole:
        if result.get("verdict") == "stable":
            result["verdict"] = "degraded"
        if merged.icmp_frag_needed:
            mtus = sorted({m for _, m in merged.icmp_frag_needed if m})
            ms = (f"下一跳 MTU {'/'.join(str(m) for m in mtus)}"
                  if mtus else "未携带 MTU 值")
            text_bits.append(
                f"抓包证据: 捕获 ICMP 需分片指示 {len(merged.icmp_frag_needed)} 个"
                f" ({ms}) — PMTU 黑洞确认")
        else:
            text_bits.append(
                "抓包证据: 大包同序号反复重传 (停滞) 且小包正常流动, 结合握手 MSS "
                "大于路径 MTU — 判 PMTU 黑洞 (分片指示 ICMP 被链路丢弃, 黑洞典型形态)")
        advice_bits.append(
            "处置后复跑 netpulse --monitor --capture slice 验证 — "
            "切片会再次自动取证, 对比前后两份报告")
        result["confidence"] = 92
        result["confidence_basis"] = "抓包证据确认 (ICMP 分片指示/大包停滞直接佐证)"
        summary_bits.append("抓包确认 PMTU 黑洞")
        _tag([e for e in events if e["type"] == "mtu_mismatch"],
             "PMTU 黑洞 (抓包确认)")
        _tag([e for e in events if e["type"] == "tcp_retrans_burst"],
             "重传源于 PMTU 黑洞 (抓包佐证)")
    elif merged.suspected_tcp_loss_burst:
        if result.get("verdict") == "stable":
            result["verdict"] = "degraded"
        text_bits.append(
            f"抓包证据: 重传占比 {merged.retrans_rate * 100:.1f}% 分布于 "
            f"{len(merged.streams)} 条流, 无大包停滞 — 链路丢包/拥塞佐证")
        advice_bits.append(
            "抓包佐证链路层丢包: 带上本报告与切片 pcap 向运营商报障 "
            "(报告含重传时序, 切片含逐包证据)")
        result["confidence"] = 85
        result["confidence_basis"] = "抓包佐证 (重传分布形态)"
        summary_bits.append("抓包佐证链路丢包")
        _tag([e for e in events if e["type"] == "tcp_retrans_burst"],
             "链路丢包/拥塞 (抓包佐证)")
    if merged.suspected_dns_slow:
        if result.get("verdict") == "stable" and not text_bits:
            result["verdict"] = "degraded"
        worst = max(r[1] - r[0] for r in merged.dns_slow_queries)
        text_bits.append(
            f"抓包证据: {len(merged.dns_slow_queries)} 次 DNS 解析超 1s "
            f"(最长 {worst:.1f}s)")
        if not result.get("confidence"):
            result["confidence"] = 85
            result["confidence_basis"] = "抓包佐证 (DNS 慢查询)"
        _tag([e for e in events if e["type"] == "dns_fail"],
             "DNS 解析慢 (抓包佐证)")
    if text_bits:
        result["conclusion_text"] = \
            (result.get("conclusion_text") or "") + "；" + "；".join(text_bits)
    if advice_bits:
        prev = result.get("advice") or ""
        result["advice"] = (prev + "\n" if prev else "") + "\n".join(advice_bits)
    if summary_bits:
        result["summary"] = \
            (result.get("summary") or "") + ", " + ", ".join(summary_bits)


def run_monitor_mode(duration_s, ext_target=None, load_url=None,
                     capture_mode=None, capture_mb=CAPTURE_DEFAULT_MB):
    """盯障模式入口 (CLI --monitor 与菜单 m 共用)。

    全文件唯一在长循环外层捕获 KeyboardInterrupt 的地方: Ctrl+C 提前结束
    也必须走统一的报告落盘路径 (装维随时可停, 数据不丢)。"""
    duration_s = max(30, min(86400, int(duration_s or 600)))
    session = MonitorSession(duration_s, ext_target, load_url=load_url)
    if not session.start():
        print(_c("  ✗ 外网 ping 启动失败, 无法开始监测 (检查 ping 命令可用性)", C_RED))
        return None
    tg = session  # noqa: F841 (保留引用便于将来扩展)
    print(_c(f"  盯障开始: 时长 {duration_s}s · 网关 {session._gw_ip or '—'} · "
             f"外网 {session._ext_ip_resolved} · DNS {session._dns_server}", C_CYAN))
    print(_c("  期间可正常使用电脑; Ctrl+C 可提前结束并生成报告", C_GRAY))
    print(_c("  统计层 (v1.7.0): 后台探测路径 MTU + TCP 重传统计 30s 采样"
             + ("; 已排定主动下载负载 (--monitor-load)" if load_url else ""),
             C_GRAY))
    # 抓包层 (v1.8.0 PR-F1): 显式 --capture 才启用; 检查链失败 → 降级提示,
    # 统计层照跑、退出码不变
    cap = None
    if capture_mode:
        # 首次使用确认 (PR-F5): 拒绝 → 降级仅统计层, 盯障照常
        if not _capture_confirm_once():
            print(_c("  已跳过抓包 (未确认), 继续仅统计层监测", C_YELLOW))
            capture_mode = None
    if capture_mode:
        cap = _PcapCaptureSession(capture_mode, capture_mb)
        if cap.precheck():
            if cap.start():
                print(_c(f"  抓包层 (v1.8.0): 已启动 ({'事件触发切片' if capture_mode == 'slice' else '全程落盘'}, "
                         f"{capture_mb}MB 上限, 接口 {cap.iface}; 仅保留包头/首 2 包 384B, 不存应用内容)",
                         C_GRAY))
            else:
                print(_c("  ✗ 抓包启动失败, 继续仅统计层监测", C_YELLOW))
                cap = None
        else:
            print(_c(f"  抓包不可用: {cap.unavailable_reason}", C_YELLOW))
            cap = None
    early = False
    tty = sys.stdout.isatty()
    mono0 = time.monotonic()
    last_heartbeat = -61
    last_poll = -6.0
    try:
        while True:
            elapsed = time.monotonic() - mono0
            if elapsed >= duration_s:
                break
            line = session.progress_line(elapsed)
            if tty:
                sys.stdout.write("\r\033[K" + line)
                sys.stdout.flush()
            elif elapsed - last_heartbeat >= 60:
                print(line)
                last_heartbeat = elapsed
            session.maybe_recheck_gateway(elapsed)
            # 事件触发切片 (PR-F2): 每 5s 增量跑一次事件检测, 新触发型事件
            # 排定切片落盘 (检测后置, 切的都是已过去窗口)
            if cap and elapsed - last_poll >= 5:
                last_poll = elapsed
                try:
                    cap.poll_events(session)
                except Exception:
                    pass       # 切片失败不影响盯障主路径
            time.sleep(1)
    except KeyboardInterrupt:
        early = True
    finally:
        if tty:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        print(_c("  收到 Ctrl+C, 提前结束监测..." if early else "  监测完成, 汇总数据...",
                 C_YELLOW if early else C_GREEN))
        session.stop()
        if cap:
            cap.stop()
    result = session.build_result(early_terminated=early)
    if cap:
        cap_block = cap.finish(result)
        if cap_block:
            result["capture"] = cap_block
            # PR-F4: 切片离线分析 → 结论联动 (失败不影响报告落盘)
            try:
                _apply_capture_evidence(result)
            except Exception:
                pass
    paths = save_monitor_report(result)
    print(_c(f"  {result['summary']}", C_GREEN))
    if paths:
        result["report_html"], result["report_json"] = paths[0], paths[1]
        for p in paths:
            print(_c(f"  ✓ {os.path.abspath(p)}", C_GREEN))
        if tty:
            try:
                webbrowser.open("file:///" + paths[0].replace("\\", "/"))
            except Exception:
                pass
    else:
        print(_c("  ✗ 报告保存失败 (目录不可写?)", C_RED))
    return result


# ============================================================
# SECTION 5: 模块注册与 CLI
# ============================================================

# 模块注册表 (key, 显示名, 检测器类)
# 顺序 = 装维工作流分类顺序 (先看 → 再测 → 后查), 序号 1-19 全局连续,
# CLI/菜单的序号解析与此保持一致。
MODULE_REGISTRY = [
    # ── 基础信息: 环境快照 ──
    ("linkspeed",  "链路速率",      LinkSpeedDetector),
    ("dhcp",       "DHCP 检测",     DHCPDetector),
    ("lan",        "LAN 设备扫描",  LANDeviceScanner),
    ("wifi",       "WiFi 分析",     WiFiAnalyzer),
    ("ipv6",       "IPv6 检测",     IPv6Tester),
    ("egress",     "多出口",        MultiEgressDetector),
    # ── 宽带测速: 带宽达标验证 (装维核心高频) ──
    ("speedtest",  "测速",          SpeedTester),
    ("bufferbloat","Bufferbloat",   BufferbloatTester),
    # iperf3: 到指定服务器的点对点吞吐 (归类 b 宽带测速, 但测的是链路吞吐非互联网宽带)
    ("iperf3",     "iperf3 吞吐",   Iperf3Tester),
    # tcpcc: 并发连接容量压测 (NAT 表上限), 与吞吐/延迟同属"容量性能"家族
    ("tcpcc",      "TCP 并发",      TCPConcurrencyTester),
    # ── 故障诊断: 定位故障根源 ──
    ("gateway",    "网关检测",      GatewayTester),
    ("external",   "外网检测",      ExternalNetworkTester),
    ("dns",        "DNS 诊断",      DNSTester),
    # web: L7 应用层体检, 紧随 DNS (域名解析完就看网页分层耗时)
    ("web",        "网页体检",      WebPageTester),
    ("arp",        "ARP 分析",      ARPAnalyzer),
    ("loop",       "环路检测",      LoopDetector),
    ("tcp",        "TCP 连接",      TCPConnectionAnalyzer),
    ("port",       "端口探测",      PortProbeTester),
    ("route",      "路由表",        RouteTableAnalyzer),
    ("tcpstats",   "TCP 传输质量",  TCPStatsTester),
    ("mtu",        "MTU 检测",      MTUDetector),
    # proxy: 代理/加速器残留清点 + 可用性探测 ("开着代理但代理没了"是断网高频根因)
    ("proxy",      "代理检测",      ProxyDetector),
    # nattype: STUN 双服务器对比判定锥形/对称型 + UDP 出网受阻检测 (游戏/P2P 排障)
    ("nattype",    "NAT 类型",      NATTypeTester),
]
MODULE_MAP = {k: (n, c) for k, n, c in MODULE_REGISTRY}

# 压力级模块 (审计 §12): 对网络/NAT 表制造显著负载, 不随 all / debug-bundle
# 静默执行 — 只在用户显式点名时运行。
STRESS_MODULE_KEYS = ("tcpcc",)


def all_module_keys():
    """all 展开口径: 全部模块去掉压力级。CLI --modules all / 交互菜单
    0-all-* / debug-bundle 三处共用, 保证口径一致。"""
    return [k for k, _, _ in MODULE_REGISTRY if k not in STRESS_MODULE_KEYS]


def _stress_excluded_hint():
    excluded = [k for k, _, _ in MODULE_REGISTRY if k in STRESS_MODULE_KEYS]
    return (f"  提示: 压力级模块 {', '.join(excluded)} 已排除, 不随 all 执行; "
            f"需要时显式指定 (如 --modules {excluded[0]})")

# 模块三大分类 (装维工作流: 先看 → 再测 → 后查)
# 每项: (分类名, keys, 一句话定位); 顺序即展示顺序
MODULE_CATEGORIES = [
    ("基础信息", ["linkspeed", "dhcp", "lan", "wifi", "ipv6", "egress"],
     "环境快照 · 看清网络状态"),
    ("宽带测速", ["speedtest", "bufferbloat", "iperf3", "tcpcc"],
     "带宽达标验证 · 装维核心高频"),
    ("故障诊断", ["gateway", "external", "dns", "web", "arp", "loop", "tcp",
                  "port", "route", "tcpstats", "mtu", "proxy", "nattype"],
     "定位故障根源"),
]
# 分类速查: key -> 分类名
MODULE_CATEGORY_OF = {k: name for name, keys, _ in MODULE_CATEGORIES for k in keys}

# 分类字母标识 (菜单 / CLI 快捷输入): a/b/c 按分类运行
# 字母顺序 = MODULE_CATEGORIES 定义顺序; 与分类名一一对应
MODULE_CATEGORY_LETTERS = ["a", "b", "c"]
MODULE_LETTER_KEYS = {}     # 字母 -> 该分类全部模块 key (按定义顺序)
MODULE_LETTER_NAME = {}     # 字母 -> 分类名
MODULE_NAME_LETTER = {}     # 分类名 -> 字母 (反向)
for _li, (_cat, _keys, _) in enumerate(MODULE_CATEGORIES):
    if _li < len(MODULE_CATEGORY_LETTERS):
        _letter = MODULE_CATEGORY_LETTERS[_li]
        MODULE_LETTER_KEYS[_letter] = list(_keys)
        MODULE_LETTER_NAME[_letter] = _cat
        MODULE_NAME_LETTER[_cat] = _letter

# ── ANSI 颜色 ──
_C_NOCOLOR = False
def _c(text, code):
    return text if _C_NOCOLOR else f"\033[{code}m{text}\033[0m"

C_BOLD   = "1"
C_GREEN  = "92"
C_RED    = "91"
C_YELLOW = "93"
C_GRAY   = "90"
C_CYAN   = "96"
C_WHITE  = "97"
C_BLUE   = "94"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _disp_width(s):
    """计算字符串在终端中的显示宽度 (ANSI 不计, 东亚宽字符计 2)。"""
    w = 0
    for ch in _ANSI_RE.sub("", s):
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def _pad_disp(s, width):
    """按显示宽度右补齐字符串到 width (用于多列对齐)。

    统一用 ASCII 空格 (1 char = 1 显示宽) 补齐, 不混全角空格。
    原因: 全角空格 (U+3000) 在等宽字体下的实际渲染宽度并不稳定 --
    Windows Consolas 下仅约 0.37 倍 ASCII 字符宽 (远小于理论 2 倍),
    跨终端/字体波动更大, 用它补齐会引入字宽漂移。
    ASCII 空格在所有终端的等宽字体下严格 1:1, 复制粘贴到任意编辑器
    (记事本/VSCode/飞书) 也保持等宽, 对齐效果稳定。
    中英混排 cell 的"模块名"宽度差由调用方在生成 cell 时预先按显示宽 pad。
    """
    need = width - _disp_width(s)
    if need <= 0:
        return s
    return s + (" " * need)


def _columnize(cells, columns=2, gap=3):
    """把若干 (可能含 ANSI 颜色) 字符串按多列排成若干行。

    行优先填充 (先左后右、再换行), 每列按最长 cell 的显示宽度对齐。
    返回字符串列表, 调用方自行加缩进后打印。

    实现细节:
      - _pad_disp 用全角空格 (1 char = 2 disp) 补齐, 与汉字同比例, 避免
        ASCII 空格 (1 char = 1 disp) 在中英混排 cell 上 pad 出多余的
        "字符数", 导致行间 char 位置不齐。
      - gap 仍用 ASCII 空格 (1 char = 1 disp), 保持列间距紧凑。
        视觉对齐靠"所有 cell 1 显示宽 = max_width"保证。
    """
    if not cells:
        return []
    columns = max(1, columns)
    width = max(_disp_width(c) for c in cells)
    rows = (len(cells) + columns - 1) // columns
    out = []
    for r in range(rows):
        parts = []
        for c in range(columns):
            i = r * columns + c
            if i < len(cells):
                parts.append(_pad_disp(cells[i], width))
        out.append((" " * gap).join(parts).rstrip())
    return out


STATUS_STYLE = {
    "完成": C_GREEN, "正常": C_GREEN,
    "警告": C_YELLOW,
    "异常": C_RED, "错误": C_RED, "超时": C_RED,
    "未检测": C_GRAY,
}


def determine_status(result):
    """根据结果字典判定状态 (只升不降: 完成 < 警告 < 异常 < 错误)。

    Bug 修复:
      - critical 判定由 all 改为 any (有任一 critical 即异常)。
      - assessment 关键词不再把已有异常降级为警告。
    """
    if not result:
        return "未检测"
    if "error" in result:
        return "错误"
    _SEV = {"完成": 0, "警告": 1, "异常": 2}
    status = "完成"

    def _raise(s):
        nonlocal status
        if _SEV.get(s, 0) > _SEV.get(status, 0):
            status = s

    # 1. 显式异常标志
    for issue_key in ("interference", "loop_detected"):
        if result.get(issue_key) is True:
            _raise("异常")

    # 2. issues 列表: 任一 critical -> 异常; 存在 warning 或字符串 issue -> 警告;
    #    纯 info 级 issue 不改变状态 (与 HTML 卡片及顶部"需关注"口径一致,
    #    避免"徽章标警告、卡片里却只有灰色[信息]"的割裂观感)。
    #    字符串 issue 视为真实问题 (MTU/Bufferbloat/IPv6/LAN/TCPQuality 用字符串)。
    issues = result.get("issues")
    if isinstance(issues, list) and issues:
        if any(isinstance(i, dict) and i.get("severity") == "critical"
               for i in issues):
            _raise("异常")
        elif any(
            (isinstance(i, dict) and i.get("severity") == "warning")
            or isinstance(i, str)
            for i in issues
        ):
            _raise("警告")

    # 3. assessment 关键词 (只升不降)
    assessment = str(result.get("assessment", ""))
    if any(w in assessment for w in ("异常", "差", "严重", "故障")):
        _raise("异常")
    elif any(w in assessment for w in ("关注", "一般", "偏低", "较低", "慢")):
        _raise("警告")
    return status


def _cli_enable_vt():
    """Windows 下启用 ANSI 虚拟终端, 让旧版 cmd 也支持颜色。

    v1.6.1: 返回是否确认启用 (非 Windows 视为终端原生支持 ANSI = True;
    输出重定向/无控制台/旧终端 = False), 让 _menu_clear 能据此决定
    是否退化 cls/clear 子进程 — 原先忽略返回值时旧 conhost 菜单会
    打出字面转义乱码且清屏回退不可达 (审查 #7)。
    """
    if sys.platform != "win32":
        return True  # POSIX 终端原生支持 ANSI 转义
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        m = ctypes.c_ulong()
        if not k.GetConsoleMode(h, ctypes.byref(m)):
            return False  # 输出重定向/无控制台: 转义写了也没意义
        return bool(k.SetConsoleMode(h, m.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return False


def _clear_screen():
    """通过 ANSI 转义清屏 (VT 模式下), 失败返回 False 让调用方降级。"""
    try:
        if sys.platform == "win32":
            # 依赖 _cli_enable_vt() 已设置 ENABLE_VIRTUAL_TERMINAL_PROCESSING
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
        else:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
        return True
    except Exception:
        return False


def _cli_status_badge(status):
    code = STATUS_STYLE.get(status, C_GRAY)
    return _c(f"[{status}]", code)


def _cli_print_result(res, verbose=False, as_json=False, key=None):
    """打印单个诊断结果 (面向一线装维人员)。

    默认模式: 只显示 ① 一句话结论 (verdict) ② 关键指标 (metrics, 按阈值着色)
    ③ 问题/警告清单。原始字段不进命令行 — 细节在 HTML/JSON 报告里。
    --verbose 打印全部原始字段 (调试用); --json 输出完整 JSON。
    """
    if as_json:
        # v1.9.2 (审查修复): _evidence 是 runner 内部过渡键, 不进机器可读输出
        # (LAST_RUN 装配时才摘出, 打印发生在此之前)
        out = {k: v for k, v in res.items() if k not in ("callback", "_evidence")}
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
        return
    # 1. 一句话结论 (客户视图 verdict 优先, 兜底 summary)
    text = None
    if key:
        pres = MODULE_PRESENTATION.get(key, {})
        vfn = pres.get("verdict_fn")
        if vfn:
            try:
                text = vfn(res)
            except Exception:
                text = None
    if not text:
        text = res.get("summary") or res.get("error") or ""
    if text:
        print(_c("  " + text, C_WHITE))
    # 2. 关键指标 (客户视图 metrics, 按 ok/warn/err 着色)
    if key and not verbose:
        pres = MODULE_PRESENTATION.get(key, {})
        mfn = pres.get("metrics_fn")
        if mfn:
            try:
                metrics = mfn(res)
                for label, value, level in metrics:
                    code = {"ok": C_GREEN, "warn": C_YELLOW,
                            "err": C_RED}.get(level, C_WHITE)
                    print(f"    {_c(label, C_GRAY)}: {_c(value, code)}")
            except Exception:
                pass
    # 3. 问题列表 (最重要的可操作信息)
    issues = res.get("issues")
    if isinstance(issues, list) and issues:
        for it in issues:
            if isinstance(it, dict):
                sev = it.get("severity", "")
                msg = it.get("message") or it.get("desc") or str(it)
                scode = C_RED if sev == "critical" else C_YELLOW
                print(_c(f"  ! [{sev}] {msg}", scode))
            else:
                print(_c(f"  ! {it}", C_YELLOW))
    # 4. 其余原始字段: 仅 --verbose 打印 (装维人员不需要, 细节进报告)
    if verbose:
        skip = {"summary", "error", "issues", "timestamp", "callback"}
        for k, v in res.items():
            if k in skip:
                continue
            if isinstance(v, (dict, list)):
                s = json.dumps(v, ensure_ascii=False, default=str)
                if len(s) > 200:
                    s = s[:200] + f"... (共 {len(s)} 字符)"
            else:
                s = str(v)
                if len(s) > 200:
                    s = s[:200] + "..."
            print(_c(f"  {k}: ", C_CYAN) + s)


def _print_module_list():
    """打印所有可用诊断模块 (按三大类分组展示, 序号全局连续 1-19, 双列排版)。

    与 interactive_menu 同款: 全局 nameMax (按 _disp_width) 让所有 cell
    模块名右端对齐到同一列, 行内两 cell 起点也一致。
    不带 (key) 段 (与 menu 一致: 防止 cmd + Consolas 字体下像素错位)。
    """
    print(_c(f"{APP_NAME} v{APP_VERSION} — 可用诊断模块:", C_BOLD))
    idx = 0
    all_names = [MODULE_MAP[k][0]
                 for _cat_keys in (kc[1] for kc in MODULE_CATEGORIES)
                 for k in _cat_keys]
    name_max_w = max((_disp_width(n) for n in all_names), default=0)
    for cat_name, keys, desc in MODULE_CATEGORIES:
        letter = MODULE_NAME_LETTER.get(cat_name, "")
        tag = _c(f"[{letter}]", C_CYAN) if letter else ""
        print()
        print(_c(f"  {tag} {cat_name}", C_BOLD) + _c(f"  {desc}", C_GRAY))
        cells = []
        for k in keys:
            idx += 1
            n = MODULE_MAP[k][0]
            name_padded = n + " " * (name_max_w - _disp_width(n))
            cells.append(
                _c(str(idx).rjust(2), C_CYAN) + ". " +
                _c(name_padded, C_WHITE))
        for line in _columnize(cells, columns=2, gap=4):
            print("    " + line)
    print()
    print(_c("  分类快捷: 输入 a/b/c 按分类运行; all / 0 / * 运行全部。", C_GRAY))


def _parse_keys(tokens, *, strict=True):
    """解析模块标识符 (key/序号/中文名) -> keys 列表。

    strict=True:  任一 token 非法立即返回 None (用于交互菜单, 整体拒绝);
    strict=False: 跳过非法 token, 仍接受合法部分 (用于 CLI 批量, 部分合法可接受)。

    与旧版的差异: 旧版 parse_choice / parse_module_names 是两个几乎一样
    的函数, 重复维护易漂移; 现统一为单函数 + 两种严格度。
    """
    if not tokens:
        return None
    valid = {k for k, _, _ in MODULE_REGISTRY}
    name_to_key = {n.lower(): k for k, n, _ in MODULE_REGISTRY}
    keys = []
    for m in tokens:
        m = (m or "").strip()
        if not m:
            continue
        if m in valid:
            keys.append(m)
        elif m.lower() in name_to_key:
            keys.append(name_to_key[m.lower()])
        elif m.lower() in MODULE_LETTER_KEYS:
            # 分类字母 (a/b/c): 展开为该分类下全部模块
            keys.extend(MODULE_LETTER_KEYS[m.lower()])
        elif m.isdigit() and 1 <= int(m) <= len(MODULE_REGISTRY):
            keys.append(MODULE_REGISTRY[int(m) - 1][0])
        else:
            if strict:
                return None
            print(_c(f"未知模块: {m}", C_RED))
    # v1.5.3: 保序去重 — 重复 token ("dns dns" / "a c c a" 分类字母重复展开)
    # 会使模块双跑、检测范围计数虚增
    return list(dict.fromkeys(keys)) or None


def parse_module_names(names):
    """解析命令行位置参数中的模块名/序号 -> keys 列表。

    非严格模式: 无效 token 打印警告后跳过, 仍接受合法部分。
    """
    return _parse_keys(names, strict=False)


# 并行执行时 print() 同步锁, 避免多线程输出交错
_PRINT_LOCK = threading.Lock()


def _safe_print(*args, **kwargs):
    """线程安全的 print (并行模式用)。"""
    with _PRINT_LOCK:
        print(*args, **kwargs)
        sys.stdout.flush()


def compute_exit_code(statuses):
    """阶段 D · v1.4.0 引入: 标准化 Exit Code.

    用法: main() 跑完诊断后, sys.exit(compute_exit_code(LAST_RUN["status"]))
    约定 (与 PowerShell/BAT/RMM/CI 一致):
      0 = 全部 OK (无异常/警告/超时)
      1 = 有警告 (warning) — 网络有可关注项, 但不阻塞
      2 = 检测出问题 (异常/错误/超时) — 客户网络真有问题
      3 = 工具执行失败 (Python 异常) — 工具自己崩了
      4 = 参数错 (argparse 已处理, 此处不返回 4)
      5 = 权限不足 (管理员权限缺失, --no-scapy 已处理)
    """
    statuses = set(statuses.values() if isinstance(statuses, dict) else statuses)
    if statuses & {"异常", "错误", "超时"}:
        return 2
    if "警告" in statuses:
        return 1
    return 0


def _export_reports(spec, rule_filter=None):
    """按逗号分隔的 spec 导出报告 (modules / diagnose 两条 CLI 路径共用)."""
    targets = [t.strip() for t in spec.split(",") if t.strip()] or [spec]
    for t in targets:
        err = export_report(t, rule_filter=rule_filter)
        if err:
            print(_c(f"  ✗ {err}", C_RED))
        else:
            print(_c(f"  ✓ 报告已导出: {os.path.abspath(_normalize_report_path(t))}", C_GREEN))


def _exit_with_status():
    """诊断跑完后按 D2 标准退出码结束 (0=OK / 1=警告 / 2=检测出问题)."""
    if LAST_RUN and LAST_RUN.get("status"):
        sys.exit(compute_exit_code(LAST_RUN["status"]))


def run_diagnostics(keys, verbose=False, as_json=False, no_color=False,
                   banner=True, install=False, parallel=False, max_workers=4,
                   pip_mirror=None):
    """执行指定模块并打印结果与汇总。返回 {key: status}。

    parallel: True 时多个模块并发执行 (--parallel)。共享状态 (LAST_RUN,
              _CMD_CACHE 等) 已为线程安全, 但 print() 通过 _safe_print 同步。
              输出策略: 启动时一行, 完成后一行, 详细 result 等所有模块结束
              后按 keys 顺序打印, 避免交错混乱。
    max_workers: 并行模式下的最大并发数 (--max-workers N)。
    pip_mirror: 显式指定 pip 镜像 (--pip-mirror)。
    """
    global _C_NOCOLOR, LAST_RUN
    _C_NOCOLOR = no_color
    _cli_enable_vt()
    # 报告「检测耗时」起点 (含系统信息采集, 与用户体感一致)
    _run_t0 = time.time()

    # 依赖预检: DHCP 完整检测需要 scapy (+Npcap)
    if "dhcp" in keys and not SCAPY_AVAILABLE and not FORCE_NO_SCAPY:
        ensure_scapy(auto_yes=install, mirror=pip_mirror)

    if banner:
        bar = "=" * 60
        print(_c(bar, C_BLUE))
        print(_c(f"  {APP_NAME} v{APP_VERSION}", C_BOLD) +
              _c("   Windows 网络诊断 · 命令行模式", C_GRAY))
        if parallel and len(keys) > 1:
            print(_c(f"  并行模式 (max_workers={max_workers})", C_GRAY))
        print(_c(bar, C_BLUE))

    # 系统信息
    sys_info = {}
    try:
        lip = get_local_ip() or "未知"
        gw = get_default_gateway() or "未知"
        dns_list = get_dns_servers() or []
        dns = (dns_list[0] if isinstance(dns_list, list) and dns_list
               else str(dns_list or "未知"))
        try:
            pub = get_public_ip() or "未知"
        except Exception:
            pub = "未知"
        # 增强: 拿到公网 IP 后查 ASN/地理位置, 拿 IPv6 公网 IP
        # 单独 try 包, 这些失败不影响主流程
        try:
            geo = get_ip_geo(pub if pub != "未知" else None)
        except Exception:
            geo = None
        try:
            pub_v6 = get_public_ipv6()
        except Exception:
            pub_v6 = None
        # geo 转成 "国家 / 省 / 市" 简洁串, asn 转成 "ASxxx 运营商"
        geo_str = ""
        asn_str = ""
        if geo:
            bits = [b for b in (geo.get("country"), geo.get("region"),
                                geo.get("city")) if b]
            geo_str = " / ".join(bits)
            asn_str = geo.get("isp", "")
            if not asn_str and geo.get("asn"):
                asn_str = geo.get("asn", "")
        sys_info = {
            "local_ip": lip,
            "gateway": gw,
            "dns": dns,
            "public_ip": pub,
            "asn": asn_str,
            "geo": geo_str,
            "ipv6_public_ip": pub_v6 or "",
        }
        extra = ""
        if geo_str:
            extra += f"    📍 {geo_str}"
        if asn_str:
            extra += f"    🏢 {asn_str}"
        if pub_v6:
            extra += f"    IPv6: {pub_v6}"
        print(_c(f"  本机IP: {lip}", C_WHITE) +
              _c(f"    网关: {gw}", C_WHITE) +
              _c(f"    DNS: {dns}", C_WHITE) +
              _c(f"    公网IP: {pub}", C_WHITE) +
              (_c(extra, C_WHITE) if extra else ""))
    except Exception as e:
        print(_c(f"  系统信息获取失败: {e}", C_GRAY))
    print(_c("-" * 60, C_GRAY))

    IS_TTY = sys.stdout.isatty()
    # 单独运行测速模块时启用终端实时可视化 (多模块/JSON/verbose/非 TTY 时关闭)
    SPEEDTEST_CONFIG["live_ui"] = (len(keys) == 1 and keys[0] == "speedtest"
                                   and IS_TTY and not as_json and not verbose)
    results = {}
    full = {}  # key -> 完整结果 dict (供报告使用)

    use_parallel = parallel and len(keys) > 1
    if use_parallel:
        results, full = _run_diagnostics_parallel(
            keys, max_workers=max_workers, total=len(keys))
    else:
        results, full = _run_diagnostics_sequential(
            keys, is_tty=IS_TTY)

    # 详细结果 (按 keys 顺序, 避免 parallel 模式输出乱序)
    for key in keys:
        res = full.get(key, {"error": "未执行"})
        status = results.get(key, "错误")
        name = MODULE_MAP.get(key, (key, key))[0]
        prefix = ""
        if use_parallel:
            prefix = ""  # parallel 模式启动/完成行已打印, 这里只打 result
        else:
            pass  # 顺序模式也已经在 detect() 前/后打了
        print(_c(f"▶ {name}", C_BOLD) + "  " + _cli_status_badge(status))
        _cli_print_result(res, verbose=verbose, as_json=as_json, key=key)

    # 汇总
    print()
    print(_c("=" * 60, C_BLUE))
    print(_c("  诊断汇总", C_BOLD))
    print(_c("-" * 60, C_GRAY))
    cnt = {}
    cells = []
    for key, st in results.items():
        n = MODULE_MAP[key][0]
        cells.append(_cli_status_badge(st) + " " + _c(n, C_WHITE))
        cnt[st] = cnt.get(st, 0) + 1
    for line in _columnize(cells, columns=2, gap=4):
        print("  " + line)
    print(_c("-" * 60, C_GRAY))
    summ = []
    if cnt.get("完成"): summ.append(_c(f"正常 {cnt['完成']}", C_GREEN))
    if cnt.get("警告"): summ.append(_c(f"警告 {cnt['警告']}", C_YELLOW))
    if cnt.get("异常"): summ.append(_c(f"异常 {cnt['异常']}", C_RED))
    if cnt.get("错误"): summ.append(_c(f"错误 {cnt['错误']}", C_RED))
    if cnt.get("超时"): summ.append(_c(f"超时 {cnt['超时']}", C_RED))
    print("  " + "   ".join(summ) if summ else "  无结果")
    print(_c("=" * 60, C_BLUE))

    # 记录本次运行的完整数据, 供报告生成使用
    # v1.9.0: Evidence 升为一等结构 — v2 分支夹带在 res 里的过渡键 _evidence
    # 在此摘出, results 保持纯净, 证据走独立的 LAST_RUN["evidence"] 映射。
    full, evidence_map = _extract_evidence_map(full)
    LAST_RUN = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "generated_at": datetime.now(),
        "system": sys_info,
        "status": dict(results),
        "results": full,
        "evidence": evidence_map,
        "keys": list(keys),
        # v1.5.0: 检测耗时与检测范围 — 只跑 3 个模块时健康分 100 容易被
        # 误读成"23 项全正常", Hero 必须显示覆盖了多少项
        "duration_ms": int((time.time() - _run_t0) * 1000),
        "total_modules": len(MODULE_MAP),
    }
    return results


# ── 模块级超时 ──
# 旧版并行/顺序执行对单个模块没有超时: Speedtest 选服可拖数分钟、某些模块
# 卡死时会拖住整个诊断。现在每个模块在 daemon 线程里跑, 到点未完成即标记
# "超时"并继续, 不再互相拖累; daemon 线程也不会阻塞进程退出。
DEFAULT_MODULE_TIMEOUT = 120.0  # 秒
MODULE_TIMEOUTS = {
    "speedtest":   180.0,  # 国内HTTP(多源×多连接) + 国内上行 + 可选 Ookla CLI (~60s)
    "bufferbloat": 120.0,
    "port":        180.0,  # 端口探测自带总时长上限, 这里只兜底
    "dhcp":        150.0,  # 可能等待 Npcap/scapy 抓包
    "lan":         150.0,
    "nattype":     45.0,   # 2 台 STUN × 2 次重试 × 2s + 出口对照
    "proxy":       30.0,   # 注册表/netsh 即时 + 探测 ≤3+8+8s
    "web":         150.0,  # _module_timeout 有动态公式, 这里只兜底
    "tcpcc":       120.0,  # 同上, 动态公式优先生效
}


def _module_detect_kwargs(key):
    """模块 detect() 的额外参数 (由 CLI/全局配置注入)。"""
    if key == "speedtest":
        return dict(
            use_speedtest_net=SPEEDTEST_CONFIG.get("use_speedtest_net", False),
            node=SPEEDTEST_CONFIG.get("node"),
            ookla_server_id=SPEEDTEST_CONFIG.get("ookla_server_id"),
            live_ui=SPEEDTEST_CONFIG.get("live_ui", False),
        )
    if key == "iperf3":
        return dict(
            server=SPEEDTEST_CONFIG.get("iperf3_server"),
            port=SPEEDTEST_CONFIG.get("iperf3_port", 5201),
            duration=SPEEDTEST_CONFIG.get("iperf3_duration", 10),
            udp=SPEEDTEST_CONFIG.get("iperf3_udp", False),
            save_report=True,
        )
    if key == "nattype":
        return dict(servers=NATTYPE_CONFIG.get("servers") or [])
    if key == "web":
        return dict(extra_targets=WEB_CONFIG.get("targets") or [])
    if key == "tcpcc":
        return dict(max_concurrency=TCPCC_CONFIG.get("max", 1600),
                    target=TCPCC_CONFIG.get("target"))
    return {}


def _module_timeout(key):
    if key == "iperf3":
        # 时长随 --iperf3-duration 动态伸缩: 双向 2×(duration + run_cmd 15s 余量)
        # + 定位/下载 iperf3.exe + 报告落盘。静态 120s 会让 duration≥50 必然超时。
        d = SPEEDTEST_CONFIG.get("iperf3_duration", 10)
        return 2 * (d + 15) + 90
    if key == "web":
        # 单目标总预算 60s / 3 并发 → 每批目标 60s + 余量
        n = 3 + len(WEB_CONFIG.get("targets") or [])
        return 30 + 60 * ((n + 2) // 3)
    if key == "tcpcc":
        # 时长随 --tcpcc-max 的级别数伸缩: 每级 (波 3~8s + 保持 1s) ×12s + 预检/回环/余量
        mx = max(50, min(8000, int(TCPCC_CONFIG.get("max", 1600) or 1600)))
        n_levels = len({l for l in TCPConcurrencyTester.LADDER_BASE if l <= mx} | {mx})
        return 30 + 12 * n_levels + 10
    return MODULE_TIMEOUTS.get(key, DEFAULT_MODULE_TIMEOUT)


def _run_module_with_timeout(key, callback):
    """在 daemon 线程中执行模块探测, 超时返回 ("超时", {error})。

    返回 (status, res_dict):
      - 正常完成: (status_zh, res_dict)
      - 模块抛异常: ("错误", {"error": ...})
      - 超过 _module_timeout(key): ("超时", {"error": ...})
    超时后模块线程继续在后台运行 (daemon, 进程退出时被强杀), 结果被丢弃,
    不影响其它模块。

    V2 双轨 (B7+): key 在 _V2_PROBES 里时, 走 probe 路径 (返回 DiagnosticResult),
    .metrics 字段填到 res_dict, .status.zh_label 作状态; 否则走旧 Tester.detect().
    """
    timeout = _module_timeout(key)
    box = {}

    # ── V2 Probe 路径 (B7 gateway 试点) ──
    if key in _V2_PROBES:
        probe_fn = _V2_PROBES[key]

        def _work_v2():
            try:
                box["result"] = probe_fn(callback=callback)
            except Exception as e:
                box["err"] = e

        t = threading.Thread(target=_work_v2, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            return "超时", {"error": f"模块执行超时（超过 {timeout:.0f} 秒）"}
        if "err" in box:
            return "错误", {"error": str(box["err"])}
        result = box["result"]
        # probe 失败 (error 非 None) 时: 状态用「错误」且错误文案回填 res —
        # 与旧 Tester 路径 determine_status({'error':…})='错误' 零差异
        # (metrics 一并保留, wrap 型 probe 的完整 results 不丢)
        if result.error is not None:
            res = dict(result.metrics or {})
            res["error"] = result.error.message
            return "错误", res
        # DiagnosticResult.metrics 兼容旧 res_dict 接口 (verdict_fn / metrics_fn / 报告)
        res = result.metrics
        if result.evidence:
            # P0-03 迁移期 (v1.8.2): Evidence 以保留键 _evidence 随 res 进入
            # LAST_RUN.results (JSON tech.raw_results 可见)。报告层直接消费
            # Evidence 后此过渡键移除。
            res = dict(res or {})
            res["_evidence"] = [e.to_dict() for e in result.evidence]
        return result.status.zh_label, res

    # ── 旧 Tester 路径 (向后兼容) ──
    name, cls = MODULE_MAP[key]
    if key == "port":
        inst = cls(targets=PORT_PROBE_CONFIG["targets"],
                   proto=PORT_PROBE_CONFIG["proto"],
                   count=PORT_PROBE_CONFIG["count"],
                   force=PORT_PROBE_CONFIG.get("force", False),
                   max_total_time=PORT_PROBE_CONFIG.get("max_total_time", 60.0),
                   max_concurrency=PORT_PROBE_CONFIG.get("max_concurrency", 8))
    else:
        inst = cls()
    detect_kwargs = _module_detect_kwargs(key)
    def _work():
        try:
            inst.detect(callback=callback, **detect_kwargs)
            box["res"] = inst.results
        except Exception as e:
            box["err"] = e

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return "超时", {"error": f"模块执行超时（超过 {timeout:.0f} 秒）"}
    if "err" in box:
        return "错误", {"error": str(box["err"])}
    return determine_status(box["res"]), box["res"]


def _extract_evidence_map(full):
    """把 v2 分支夹带在 res 里的过渡键 _evidence 摘出 (v1.9.0)。

    Evidence 是一等结构, 不随模块 results 落盘/导出 — 返回 (results, evidence):
      results   去掉 _evidence 后的模块结果 dict (原 full 语义)
      evidence  {module_key: [Evidence.to_dict(), ...]} (无证据的模块不出现)
    """
    results, evidence = {}, {}
    for k, v in (full or {}).items():
        if isinstance(v, dict) and "_evidence" in v:
            ev = v.get("_evidence")
            v = {kk: vv for kk, vv in v.items() if kk != "_evidence"}
            if isinstance(ev, list) and ev:
                evidence[k] = ev
        results[k] = v
    return results, evidence


def _run_diagnostics_sequential(keys, is_tty):
    """顺序模式: 保留 TTY 实时进度行 (\\r\\033[K 刷新), 详细 result 留给主循环统一打。
    每个模块有独立超时 (_run_module_with_timeout), 单个模块卡死不会拖住整个流程。"""
    results = {}
    full = {}
    for key in keys:
        name, cls = MODULE_MAP[key]
        if is_tty:
            sys.stdout.write(_c(f"  正在 {name} …", C_GRAY))
            sys.stdout.flush()
        else:
            print(_c(f"  正在 {name} …", C_GRAY))
        if is_tty:
            def _cb(msg, _n=name):
                sys.stdout.write("\r\033[K" + _c(f"  … {msg}", C_GRAY))
                sys.stdout.flush()
        else:
            _cb = lambda msg: None
        try:
            status, res = _run_module_with_timeout(key, _cb)
        except Exception as e:
            status, res = "错误", {"error": str(e)}
        if is_tty:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        if status in ("错误", "超时"):
            print(_c(f"▶ {name}", C_BOLD) + "  " + _cli_status_badge(status))
            print(_c(f"  {res.get('error', status)}", C_RED))
        results[key] = status
        full[key] = res
    return results, full


def _run_diagnostics_parallel(keys, max_workers, total):
    """并行模式: 4 worker 并发跑, 启动和完成行都按 keys 顺序打印。

    设计要点:
      - 启动行: 主线程在 submit 前按 keys 顺序打 (1, 2, 3, ..., 18 整齐一行下来)
      - 完成行: worker 完成时只存结果, 不立即打印; 主线程等所有完成后按 keys 顺序遍历
        打 (1, 2, 3, ..., 18 整齐一行下来)
      - 每个模块有独立超时 (_run_module_with_timeout), 慢模块卡死只影响自己,
        不再拖累其它 worker
      - print() 走 _safe_print (lock) 避免交错
      - 共享状态 (_CMD_CACHE / _LOCAL_SUBNET_CACHE / _DECODE_CACHE / DNS socket)
        均为只读 / GIL-safe / thread-local, 多个 detector 并发安全
    """
    results = {}
    full = {}
    completed = {}       # key -> (name, status, res)
    completed_lock = threading.Lock()

    def _run_one(key):
        name, cls = MODULE_MAP[key]
        status, res = _run_module_with_timeout(key, lambda msg: None)
        # 存结果, 不立即打 (主线程按 keys 顺序统一打)
        with completed_lock:
            completed[key] = (name, status, res)
        return key

    # 启动行: 主线程按 keys 顺序打 (1-19 整齐一行)
    for i, key in enumerate(keys, 1):
        name = MODULE_MAP[key][0]
        _safe_print(_c(f"  [{i}/{total}] 正在 {name} …", C_GRAY))

    # 等待所有 worker 完成 (每个 worker 内部自带超时, 不会无限等)
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as ex:
        futs = [ex.submit(_run_one, k) for k in keys]
        for fut in as_completed(futs):
            fut.result()  # 等待, 不打印

    # 完成行: 主线程按 keys 顺序打 (1-19 整齐一行)
    for i, key in enumerate(keys, 1):
        if key not in completed:
            # 理论上不会到这里 (except 块也存了), 但兜底
            continue
        name, status, res = completed[key]
        _safe_print(_c(f"  [{i}/{total}] ✓ {name}", C_BOLD) + "  "
                    + _cli_status_badge(status))
        results[key] = status
        full[key] = res
    return results, full


# ============================================================
# SECTION: 诊断报告生成与导出 (HTML / JSON)
# ============================================================

# ============================================================
# 客户视图 / 技术视图分离
# ============================================================
# 老的 render_report_* 直接吃 "扁平 result 字典", 把所有字段拍平成 KV 表,
# 结果就是客户看到 "ping: sent: 30; rtts: 113, 4, 11, 15, ..." 这种技术细节。
# 新设计:
#   - 报告生成面向"客户" (网络维护工程师给客户/老板看)
#   - 每个模块有专门的 verdict + 关键指标 + 影响/建议, 技术细节折叠
#   - JSON 报告里同时给 raw 原始数据 + 阈值定义, 给工程师/脚本用
#
# 配置式写法: 每个模块的"客户视图"由 MODULE_PRESENTATION 配置,
# 没配置的模块走 _generic_presentation 用 result.summary + 2-3 个数字字段兜底。


# 阈值集中: 健康分 / 颜色判定 / 客户报告"超过阈值"提示都引用这里
# 注意: 跟模块内部的判定 (gateway.assessment 等) 不一定 1:1 对应,
#       这里是"客户视角的阈值"——给客户看的警示线, 不一定等于工程判定阈值。
THRESHOLDS = {
    "gateway": {
        "ping.avg_ms":   {"warn": 10,  "err": 30,  "unit": "ms", "label": "平均延迟",
                          "lower_better": True},
        "ping.loss_pct": {"warn": 1,   "err": 5,   "unit": "%",  "label": "丢包率",
                          "lower_better": True},
        "ping.jitter_ms":{"warn": 5,   "err": 20,  "unit": "ms", "label": "抖动",
                          "lower_better": True},
        "ping.max_ms":   {"warn": 100, "err": 300, "unit": "ms", "label": "最大延迟",
                          "lower_better": True},
    },
    "external": {
        "avg_rtt_ms":     {"warn": 50,  "err": 150, "unit": "ms", "label": "平均延迟",
                           "lower_better": True},
        "avg_loss_pct":   {"warn": 1,   "err": 5,   "unit": "%",  "label": "平均丢包",
                           "lower_better": True},
        "tcp_ok_count":   {"warn_total": True, "label": "TCP 可达数",
                           "lower_better": False},
    },
    "dns": {
        "avg_time_ms":    {"warn": 50,  "err": 200, "unit": "ms", "label": "平均响应",
                           "lower_better": True},
    },
    "wifi": {
        "network_count":  {"warn": 8,   "err": 15,  "label": "WiFi 邻居数",
                           "lower_better": True},
    },
    "speedtest": {
        "download_mbps":  {"warn": 10,  "err": 1,   "unit": "Mbps", "label": "下载速率",
                           "lower_better": False},
    },
    "bufferbloat": {
        "bloat_ms":       {"warn": 30,  "err": 100, "unit": "ms", "label": "延迟增加",
                           "lower_better": True},
    },
    "linkspeed": {
        # 有线: < 100 = 警告; WiFi: < 54 = 警告 (按 is_wifi 分档)
    },
    "tcpstats": {
        "retrans_rate_pct":{"warn": 1,  "err": 5,   "unit": "%", "label": "重传率",
                            "lower_better": True},
    },
    "web": {
        "avg_ttfb_ms":  {"warn": 500,  "err": 2000, "unit": "ms", "label": "平均首字节",
                         "lower_better": True},
    },
    "tcpcc": {
        "max_sustained": {"warn": 1024, "err": 512, "label": "最大可持续并发",
                          "lower_better": False},
    },
}


# 每个模块的"客户视图"配置: 一句话结论怎么拼、关键指标取哪几个、
# 阈值提示怎么写。统一格式:
#   {
#     "verdict_fn":   callable(res) -> str  # 一句话结论
#     "metrics":      [  # 关键指标
#         (label, value_fn, level_fn)  # level_fn(value) -> "ok"/"warn"/"err"
#     ]
#     "issues_fn":    callable(res) -> list[dict]  # [{severity, text, impact, action}]
#     "tech_keys":    ["rtts", "ping", ...]  # 折叠区域展示哪些原始 key
#   }
def _verdict_gateway(res):
    if "error" in res:
        return res.get("error", "检测失败")
    p = res.get("ping", {})
    gw = res.get("gateway", "")
    # <1ms 时 ping 输出整数 0, 显示 "平均 <1ms" 而非误导性的 0ms (v1.9.3)
    a = p.get("avg_ms", "?")
    at = "<1" if (isinstance(a, (int, float)) and a < 1 and p.get("rtts")) else a
    return (f"网关 {gw}: 平均 {at}ms, "
            f"丢包 {p.get('loss_pct', '?')}%, 抖动 {p.get('jitter_ms', '?')}ms")


def _metrics_gateway(res):
    if "error" in res:
        return []
    p = res.get("ping", {})
    th = THRESHOLDS["gateway"]
    out = []

    def _level(key, val):
        cfg = th.get(key, {})
        if "warn" in cfg and cfg.get("lower_better", True):
            if val >= cfg["err"]:
                return "err"
            if val >= cfg["warn"]:
                return "warn"
        return "ok"

    out.append(("平均延迟", f"{p.get('avg_ms', '?')} ms", _level("ping.avg_ms", p.get("avg_ms", 0))))
    out.append(("丢包率",   f"{p.get('loss_pct', '?')}%", _level("ping.loss_pct", p.get("loss_pct", 0))))
    out.append(("抖动",     f"{p.get('jitter_ms', '?')} ms", _level("ping.jitter_ms", p.get("jitter_ms", 0))))
    out.append(("最大延迟", f"{p.get('max_ms', '?')} ms", _level("ping.max_ms", p.get("max_ms", 0))))
    return out


def _issues_gateway(res):
    if "error" in res:
        return [{"severity": "异常", "text": res["error"],
                 "impact": "无法评估网关质量", "action": "检查网络连接是否正常"}]
    out = []
    for issue in res.get("issues", []) or []:
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            # 把 ping 原始数据塞进 raw_summary, 让顶部 todo 块能直接显示
            # "20 发 / 19 收 / 1 丢" (不必展开技术细节也能看到依据)
            raw_summary = None
            # 两种 id 形态都认: 旧 GatewayTester 下划线 (gateway_packet_loss)
            # 与 v2 probe 点分 (gateway.packet_loss)
            if issue.get("type") in ("gateway_packet_loss", "gateway.packet_loss"):
                p = res.get("ping", {}) or {}
                sent = p.get("sent")
                recv = p.get("received")
                if sent is not None and recv is not None:
                    raw_summary = f"{sent} 发 / {recv} 收 / {sent - recv} 丢"
            out.append({
                "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": issue.get("action", ""),
                "type": issue.get("type", ""),
                "raw_summary": raw_summary,
            })
    return out


def _verdict_external(res):
    if "error" in res:
        return res.get("error", "检测失败")
    avg_rtt = res.get("avg_rtt_ms", 0)
    avg_loss = res.get("avg_loss_pct", 0)
    tcp_ok = res.get("tcp_ok", 0)
    tcp_total = res.get("tcp_total", 0)
    unreachable = res.get("unreachable_count", 0)
    blocked = res.get("icmp_blocked_count", 0)
    parts = [f"平均延迟 {avg_rtt}ms, 丢包 {avg_loss}%"]
    if unreachable:
        parts.append(f"{unreachable} 个目标不可达")
    if blocked:
        parts.append(f"{blocked} 个目标被禁拼 (ICMP 防火墙)")
    return "外网检测: " + ", ".join(parts) + f" (TCP {tcp_ok}/{tcp_total})"


def _metrics_external(res):
    out = []
    avg_rtt = res.get("avg_rtt_ms", 0)
    avg_loss = res.get("avg_loss_pct", 0)
    tcp_ok = res.get("tcp_ok", 0)
    tcp_total = res.get("tcp_total", 0)

    def _lvl(val, warn, err, lower=True):
        if lower:
            if val >= err: return "err"
            if val >= warn: return "warn"
        else:
            if val <= err: return "err"
            if val <= warn: return "warn"
        return "ok"

    out.append(("平均延迟", f"{avg_rtt} ms",
                _lvl(avg_rtt, 50, 150)))
    out.append(("平均丢包", f"{avg_loss}%",
                _lvl(avg_loss, 1, 5)))
    out.append(("TCP 可达", f"{tcp_ok}/{tcp_total}",
                "ok" if tcp_ok == tcp_total else
                "warn" if tcp_ok > 0 else "err"))
    # TCP RTT 异常目标数 (TCP 握手 >500ms 说明 SYN 队列堆积或链路劣化)
    targets = res.get("targets") or []
    high_tcp_rtt_count = sum(1 for t in targets
                             if t.get("tcp_reachable") and t.get("tcp_rtt_ms")
                             and t["tcp_rtt_ms"] > 500)
    if high_tcp_rtt_count:
        out.append(("TCP延迟异常", f"{high_tcp_rtt_count} 个",
                    "warn", "TCP 握手 >500ms, 可能 SYN 限速或链路拥塞"))
    if res.get("unreachable_count", 0):
        out.append(("不可达目标", f"{res['unreachable_count']} 个", "err"))
    elif res.get("icmp_blocked_count", 0):
        # "禁拼目标" 不是故障 (对方防火墙策略, 不影响 TCP), 用 info 灰色而非 warn 橙色
        # 与 explain 文本 "不算故障" 一致
        out.append(("禁拼目标", f"{res['icmp_blocked_count']} 个", "info", "对方防火墙禁 ping, TCP 实测可达, 不算故障"))
    return out


def _verdict_dns(res):
    if "error" in res:
        return res.get("error", "检测失败")
    if res.get("dns_hijack"):
        return f"DNS 疑似劫持 ({res.get('success_count', 0)}/{res.get('total_count', 0)} 成功)"
    return (f"DNS 测试: {res.get('success_count', 0)}/{res.get('total_count', 0)} 成功, "
            f"平均 {res.get('avg_time_ms', 0)}ms")


def _metrics_dns(res):
    out = []
    succ = res.get("success_count", 0)
    tot = res.get("total_count", 0)
    avg = res.get("avg_time_ms", 0)

    out.append(("成功率", f"{succ}/{tot}",
                "err" if succ < tot * 0.5 else "warn" if succ < tot else "ok"))
    out.append(("平均响应", f"{avg} ms",
                "err" if avg >= 200 else "warn" if avg >= 50 else "ok"))
    # 按服务器选最快的 3 个
    per = res.get("per_server", [])
    for s in sorted(per, key=lambda x: x.get("avg_ms", 9999))[:3]:
        st = s.get("status", "正常")
        out.append((s.get("dns_name") or s.get("dns_server", "?"),
                    f"{s.get('avg_ms', '?')} ms ({s.get('ok', 0)}/{s.get('total', 0)})",
                    "err" if st in ("不可用", "部分失败") else "ok"))
    return out


def _issues_dns(res):
    out = []
    if res.get("dns_hijack"):
        out.append({
            "severity": "异常",
            "text": "系统 DNS 对公网域名返回私有/保留 IP, 疑似 DNS 劫持/透明代理",
            "impact": "可能被劫持到错误的服务器, 隐私泄露, 部分网站访问异常",
            "action": "检查路由器 DNS 设置, 改用 AliDNS (223.5.5.5) / DNSPod (119.29.29.29)"
        })
    succ = res.get("success_count", 0)
    tot = res.get("total_count", 0)
    if tot and succ < tot * 0.8:
        out.append({
            "severity": "警告" if succ >= tot * 0.5 else "异常",
            "text": f"DNS 解析失败 {tot - succ}/{tot}",
            "impact": "网页/APP 加载慢, 部分域名可能无法访问",
            "action": "尝试更换 DNS 服务器 (阿里/腾讯/114)"
        })
    # 慢响应: 与 assessment "DNS 响应慢" (avg>100ms) 口径一致, 补出卡片行,
    # 避免"徽章警告、卡片无内容" (该场景成功率正常时原实现不输出任何 issue)
    avg = res.get("avg_time_ms", 0)
    if tot and succ >= tot * 0.8 and avg > 100:
        out.append({
            "severity": "警告",
            "text": f"DNS 平均响应 {avg:.0f}ms 较慢",
            "impact": "网页/APP 首次加载可能偏慢",
            "action": "尝试更换 DNS 服务器 (阿里/腾讯/114)"
        })
    # info 级: 不同 DNS 解析结果不一致 (多为 CDN 轮询, 正常现象) —
    # 原实现丢弃了这条原始 info, 导致顶部"信息项"计数与卡片内容对不上
    for issue in res.get("issues", []) or []:
        if isinstance(issue, dict) and issue.get("type") == "dns_inconsistent":
            out.append({
                "severity": "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": "",
            })
    return out


def _verdict_wifi(res):
    n = res.get("network_count", 0)
    inter = res.get("overall_interference", "正常")
    best = res.get("best_2g_channel") or {}
    best_ch = best.get("channel") if isinstance(best, dict) else None
    s = f"发现 {n} 个 WiFi 网络, 干扰等级: {inter}"
    if best_ch:
        s += f", 建议信道: {best_ch}"
    return s


def _metrics_wifi(res):
    n = res.get("network_count", 0)
    inter = res.get("overall_interference", "正常")
    cur = res.get("current_channel")
    best = res.get("best_2g_channel") or {}
    best_ch = best.get("channel") if isinstance(best, dict) else None
    # 未连接 WiFi 时没有扫描数据, "邻居数 0"是误导 — 不出指标卡,
    # 由卡片里的提示行说明 "未连接属正常现象"
    if not cur and not n:
        return []
    out = [
        ("当前信道", f"{cur}" if cur else "未连接"),
        ("邻居数", f"{n} 个",
         "err" if n >= 15 else "warn" if n >= 8 else "ok"),
        ("干扰等级", inter,
         "err" if "严重" in inter else "warn" if "高" in inter or "存在" in inter else "ok"),
    ]
    if best_ch:
        out.append(("推荐信道", f"{best_ch}"))
    return out


def _issues_wifi(res):
    out = []
    for issue in res.get("issues", []) or []:
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            out.append({
                "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": issue.get("action", ""),
            })
    return out


def _verdict_speedtest(res):
    def _err_short(text):
        text = str(text)
        return text[:40] + ("…" if len(text) > 40 else "")
    if "error" in res:
        for k in ("speedtest", "http"):
            sub = res.get(k, {})
            if "error" in sub:
                return f"测速失败 ({k}): {_err_short(sub['error'])}"
        # v1.5.3: 顶层 error 同样截断 — 执行器把异常 str(exc) 整包塞进 error 时
        # 可上百字符, 原样进结论正是 v1.5.1 要消灭的"像代码崩溃"噪声
        err = _err_short(res.get("error", ""))
        return f"测速失败: {err}" if err else "测速失败"
    # 优先用 Ookla 结果作为结论 (更具权威性)
    ookla = res.get("speedtest")
    if isinstance(ookla, dict) and "error" not in ookla and ookla.get("download_mbps"):
        dl = ookla.get("download_mbps", 0)
        ul = ookla.get("upload_mbps", 0)
        lat = ookla.get("server_latency_ms", 0)
        server = ookla.get("server", "—")
        base = f"Ookla 官方测速: ↓{dl:.1f} Mbps ↑{ul:.1f} Mbps ({lat:.0f}ms, {server})"
        if ookla.get("valid") is False:
            base += f" (选点海外 {ookla.get('server_cc', '?')}, 结果仅供参考)"
        return base
    # 回退: HTTP + 国内上行
    base = res.get("summary", "测速")
    if ookla is None:
        base += " (未启用 Ookla 官方测速, 加 --speedtest-net 可对照参考)"
    elif isinstance(ookla, dict) and "error" in ookla:
        base += f" (Ookla 测速失败: {_err_short(ookla['error'])})"
    return base


def _metrics_speedtest(res):
    """测速关键指标 — 优先用 Ookla 官方测速结果, 回退到 HTTP/国内上行。

    Ookla 是官方标准测速 (交互菜单默认启用), 结果更具权威性;
    HTTP/国内上行作为回退 (CLI 未加 --speedtest-net 或 Ookla 失败时)。
    """
    out = []
    if "error" in res:
        return out
    # 判断 Ookla 结果是否可用 (有数据且无 error)
    ookla = res.get("speedtest")
    use_ookla = (isinstance(ookla, dict) and "error" not in ookla
                 and ookla.get("download_mbps"))

    if use_ookla:
        down = ookla.get("download_mbps")
        up = ookla.get("upload_mbps")
        lat = ookla.get("server_latency_ms")
        jit = ookla.get("jitter_ms")
        if down:
            out.append(("下载", f"{down} Mbps", "ok" if down >= 10 else "warn"))
        if up is not None:
            out.append(("上传", f"{up} Mbps", "ok" if up >= 5 else "warn"))
        if lat is not None:
            out.append(("延迟", f"{lat:.0f} ms", "ok" if lat < 30 else "warn"))
        if jit is not None:
            out.append(("抖动", f"{jit:.1f} ms", "ok" if jit < 5 else "warn"))
        out.append(("测速方式", "Ookla 官方", "ok"))
    else:
        # 回退: HTTP 下载 + 国内上行
        down = res.get("download_mbps")
        up = res.get("upload_mbps")
        idle = res.get("idle_rtt_ms")
        grade = res.get("bufferbloat_grade") or ""
        if down:
            out.append(("下载", f"{down} Mbps", "ok" if down >= 10 else "warn"))
        if up is not None:
            out.append(("上传", f"{up} Mbps", "ok" if up >= 5 else "warn"))
        if idle is not None:
            out.append(("延迟(网关)", f"{idle:.0f} ms",
                        "ok" if idle < 30 else "warn"))
        if grade:
            lv = "ok" if grade.startswith(("A", "B")) else "warn"
            g0 = grade.split(" ", 1)[0]
            g_rest = grade[len(g0):].strip(" ()")
            out.append(("缓冲膨胀", g0, lv, g_rest or "负载时延迟增加量"))
        out.append(("测速方式", "国内HTTP+上行", "ok"))

    # 预估宽带 (两种方式都显示)
    est = res.get("estimated_bandwidth") or {}
    if est.get("text"):
        out.append(("预估宽带", est["text"], "ok"))
    return out


def _verdict_iperf3(res):
    if "error" in res:
        err = str(res.get("error", ""))
        # 未配置服务器不是故障: 给客户能看懂的一句话, CLI 用法放括号里弱化
        if "未指定" in err:
            return ("本次未测试 — 需要指定一台 iperf3 服务器 "
                    "(内网/专线验收时配置)")
        return res.get("error", "iperf3 测试失败")
    if res.get("udp"):
        if (res.get("download_jitter_ms") is None
                and res.get("upload_jitter_ms") is None):
            return "iperf3 UDP 无有效结果"
    elif not res.get("download_mbps") and not res.get("upload_mbps"):
        return "iperf3 无有效结果"
    return res.get("summary", "iperf3 链路吞吐")


def _metrics_iperf3(res):
    """iperf3 关键指标: 明确标注是到服务器的链路吞吐 (非宽带); UDP 模式给抖动/丢包。"""
    out = []
    if "error" in res:
        return out
    if res.get("udp"):
        for side, jit, loss in (("下载", res.get("download_jitter_ms"), res.get("download_loss_pct")),
                                 ("上传", res.get("upload_jitter_ms"), res.get("upload_loss_pct"))):
            if jit is None and loss is None:
                if res.get(f"{side}_error"):
                    out.append((side, res[f"{side}_error"], "warn"))
                continue
            out.append((f"{side}抖动", f"{jit} ms",
                        "err" if (jit or 0) > 100 else "warn" if (jit or 0) > 30 else "ok"))
            out.append((f"{side}UDP丢包", f"{loss}%",
                        "err" if (loss or 0) > 5 else "warn" if (loss or 0) > 1 else "ok"))
    else:
        dl = res.get("download_mbps")
        ul = res.get("upload_mbps")
        if dl is not None:
            out.append(("下载(到服务器)", f"{dl} Mbps", "ok"))
        if ul is not None:
            out.append(("上传(到服务器)", f"{ul} Mbps", "ok"))
        if res.get("download_error"):
            out.append(("下载", res["download_error"], "warn"))
        if res.get("upload_error"):
            out.append(("上传", res["upload_error"], "warn"))
    out.append(("链路", f"{res.get('server')}:{res.get('port')}", "ok"))
    out.append(("时长", f"{res.get('duration_s')} s", "ok"))
    out.append(("说明", "UDP 抖动/丢包" if res.get("udp") else "链路吞吐非宽带", "ok"))
    return out


def _verdict_bufferbloat(res):
    if "error" in res:
        return res.get("error", "检测失败")
    return res.get("summary", "Bufferbloat 检测")


def _metrics_bufferbloat(res):
    if "error" in res:
        return []
    idle = res.get("idle_rtt_ms", 0)
    loaded = res.get("loaded_rtt_ms", 0)
    bloat = res.get("bloat_ms", 0)
    grade = res.get("grade", "")
    load_warning = res.get("load_warning", False)
    out = [
        ("空闲延迟", f"{idle} ms"),
        ("负载延迟", f"{loaded} ms",
         "err" if load_warning else
         "err" if bloat >= 100 else "warn" if bloat >= 30 else "ok"),
        ("延迟增加", f"+{bloat} ms" if bloat >= 0 else f"{bloat} ms",
         "err" if load_warning else
         "err" if bloat >= 100 else "warn" if bloat >= 30 else "ok"),
    ]
    if grade:
        out.append(("评级", grade.split(" ")[0] if " " in grade else grade,
                    "err" if load_warning else
                    "err" if "F" in grade or "D" in grade else
                    "warn" if "C" in grade else "ok"))
    if load_warning:
        out.append(("备注", "负载未建立，结果不可信", "err"))
    return out


def _issues_bufferbloat(res):
    if "error" in res:
        return []
    if res.get("load_warning"):
        return [{
            "severity": "警告",
            "text": "Bufferbloat 检测未能建立有效负载（测速源不可用）",
            "impact": "负载下延迟未实际测量，检测结果不可信",
            "action": ("检查外网连通性后重试；或手动打满带宽（如用 speedtest）"
                       "后观察网关延迟")
        }]
    bloat = res.get("bloat_ms", 0)
    if bloat >= 30:
        return [{
            "severity": "警告" if bloat < 100 else "异常",
            "text": f"Bufferbloat: 负载下延迟增加 {bloat}ms",
            "impact": "带宽跑满时其它设备延迟剧增 (视频会议/游戏会卡)",
            "action": ("① 路由器开启 QoS / SQM (智能队列管理) "
                       "② 限制单设备最大带宽 "
                       "③ 考虑升级到支持 SQM 的路由器固件 (OpenWrt/iKuaiOS)")
        }]
    return []


def _verdict_linkspeed(res):
    """链路速率结论。
    旧版只看 issues 数量, 即便所有网卡都协商到百兆也报"速率正常"。
    现版基于 metrics 等级 (err/warn/ok) 综合判定: 优先反馈最严重的网卡档位。
    """
    adapters = res.get("adapters", [])
    n = len(adapters)
    issues = res.get("issues", [])
    up_adapters = [a for a in adapters if a.get("status") in ("Up", "已启用")]
    # 统计每个网卡的协商速率档位
    if up_adapters:
        # 按 is_wifi 分档: 有线 ≥1000 ok / ≥100 warn / <100 err; WiFi ≥150 ok / ≥54 warn / <54 err
        # VPN/虚拟接口单独识别, 不当作"有线"评估档位 (VPN 隧道速率不代表物理链路)
        worst = "ok"
        worst_kinds = []  # [(kind, name, speed, level)]
        for a in up_adapters:
            sp = a.get("speed_mbps", 0) or 0
            is_wifi = bool(a.get("is_wifi"))
            desc = (a.get("description") or "").lower()
            name_lower = (a.get("name") or "").lower()
            is_virt = any(kw in desc or kw in name_lower
                          for kw in ("zerotier", "tailscale", "wireguard",
                                     "tap-windows", "vpn-adapter", "cisco anyconnect",
                                     "forticl", "globalprotect", "openvpn",
                                     "nordvpn", "expressvpn", "hamachi"))
            if is_wifi:
                lvl = "ok" if sp >= 150 else "warn" if sp >= 54 else "err"
                kind = "WiFi"
            elif is_virt:
                lvl = "ok"  # VPN 虚拟接口档位不扣分
                kind = "虚拟"
            else:
                lvl = "ok" if sp >= 1000 else "warn" if sp >= 100 else "err"
                kind = "有线"
            worst_kinds.append((kind, a.get("name", "?"), sp, lvl))
            # 计算最差等级 (err > warn > ok)
            rank = {"ok": 0, "warn": 1, "err": 2}
            if rank[lvl] > rank[worst]:
                worst = lvl
        # 拼接 verdict
        if issues:
            # 内部等级 (ok/warn/err) 映射为中文, 不把代码标识泄漏给客户
            worst_cn = {"ok": "正常", "warn": "偏低", "err": "异常"}[worst]
            return f"检测到 {n} 个适配器, {len(issues)} 个问题; 最差速率档位: {worst_cn}"
        if worst == "err":
            # 标注最低的适配器
            slow = [w for w in worst_kinds if w[3] == "err"]
            slow_str = ", ".join(f"{w[0]}·{w[1]} {w[2]} Mbps" for w in slow)
            return f"检测到 {n} 个适配器, 速率档位异常: {slow_str}"
        if worst == "warn":
            slow = [w for w in worst_kinds if w[3] == "warn"]
            slow_str = ", ".join(f"{w[0]}·{w[1]} {w[2]} Mbps" for w in slow)
            return f"检测到 {n} 个适配器, 部分档位偏低 (千兆期望下百兆): {slow_str}"
        return f"检测到 {n} 个适配器, 速率档位正常"
    if issues:
        return f"检测到 {n} 个适配器, {len(issues)} 个问题"
    return f"检测到 {n} 个适配器, 无在线网卡"


def _metrics_linkspeed(res):
    out = []
    for a in res.get("adapters", []):
        if a.get("status") not in ("Up", "已启用"):
            continue
        speed = a.get("speed_mbps", 0)
        # 接口分类: VPN 虚拟接口单独标识 (避免被误以为是物理网线速率)
        desc = (a.get("description") or "").lower()
        name_lower = (a.get("name") or "").lower()
        # 关键字选具体的 VPN/隧道产品名, 避免误伤正常网卡
        # (不要写 "virtual", 太宽, 会把 VirtualBox Host-Only 这种本地桥接网误判)
        is_virt = any(kw in desc or kw in name_lower
                      for kw in ("zerotier", "tailscale", "wireguard",
                                 "tap-windows", "vpn-adapter", "cisco anyconnect",
                                 "forticlient", "globalprotect", "openvpn",
                                 "nordvpn", "expressvpn", "hamachi"))
        if a.get("is_wifi"):
            kind = "WiFi"
            hint = ""
            level = "ok" if speed >= 150 else "warn" if speed >= 54 else "err"
            if level == "warn":
                hint = "档位偏低 (54-150 Mbps, 千兆环境期望更高)"
            elif level == "err":
                hint = "档位过低 (<54 Mbps, 远低于预期)"
        elif is_virt:
            kind = "虚拟"
            hint = "VPN/虚拟网卡速率, 不代表物理链路"
            level = "ok"  # 虚拟网卡档位不扣分
        else:
            kind = "有线"
            hint = ""
            level = "ok" if speed >= 1000 else "warn" if speed >= 100 else "err"
            if level == "warn":
                hint = "协商到百兆, 千兆环境应达 1000 Mbps"
            elif level == "err":
                hint = "协商速率过低 (<100 Mbps), 检查网线/水晶头"
        # 有 hint 时占位, 避免 _present_module 用通用 "略超阈值" 覆盖
        out.append((f"{kind} · {_short_iface(a.get('name', '?'))}",
                    f"{speed} Mbps", level, hint))
    wifi = res.get("wifi_details", {})
    if wifi.get("signal_pct") is not None:
        sig = wifi["signal_pct"]
        out.append(("WiFi 信号", f"{sig}%",
                    "ok" if sig >= 60 else "warn" if sig >= 30 else "err"))
    nic = res.get("nic_errors") or {}
    errs = nic.get("total_errors")
    if errs:                                   # 0/None 都不展示 (统计不可用时打扰)
        out.append(("网卡错误", f"{errs} (自开机)",
                    "err" if errs > 100 else "warn"))
    return out


def _issues_linkspeed(res):
    out = []
    for issue in res.get("issues", []):
        if isinstance(issue, dict):
            action = ("换网线/换端口后重跑对比 (错误清零需重启); 持续增长则网卡"
                      "或对端端口硬件故障" if issue.get("type") == "nic_errors"
                      else "检查物理连接或网卡驱动")
            out.append({
                "severity": "警告" if issue.get("severity") == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": action
            })
    return out


def _verdict_loop(res):
    if "error" in res:
        return res.get("error", "检测失败")
    n_warn = res.get("warning_count", 0)
    if res.get("loop_detected"):
        return "发现疑似网络环路!"
    return f"未发现环路 ({n_warn} 个警告)" if n_warn else "未发现网络环路"


def _metrics_loop(res):
    # ARP 条目数与结论无关 (ARP 模块已展示), 正常时不指标卡;
    # 只有发现环路才出状态卡
    out = []
    if res.get("loop_detected"):
        out.append(("环路状态", "发现疑似环路", "err"))
    return out


def _issues_loop(res):
    out = []
    for issue in res.get("issues", []):
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            out.append({
                "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": "联系网络管理员排查物理连接"
            })
    return out


def _verdict_dhcp(res):
    if "error" in res:
        return res.get("error", "检测失败")
    n = len(res.get("servers", []))
    inter = res.get("interference", False)
    if inter:
        return f"发现 {n} 个 DHCP 服务器 - 存在多服务器干扰!"
    method = res.get("method", "")
    suffix = ""
    if "ipconfig" in method:
        suffix = " (scapy 不可用降级, 仅看到当前 DHCP)"
    return f"发现 {n} 个 DHCP 服务器 - 正常{suffix}"


def _metrics_dhcp(res):
    # 结论里已有服务器数说明, 正常情况不再单独出指标卡 (省空间);
    # 只有发现干扰/多服务器异常时才展示卡片
    n = len(res.get("servers", []))
    out = []
    if n > 1:
        out.append(("DHCP 服务器", f"{n} 个", "err"))
    if res.get("interference"):
        out.append(("干扰", "存在", "err"))
    return out


def _issues_dhcp(res):
    out = []
    if res.get("interference"):
        out.append({
            "severity": "异常",
            "text": "检测到多个 DHCP 服务器响应",
            "impact": "可能随机获取到错误 IP, 导致网络间歇性中断",
            "action": "① 关闭未授权的 DHCP 服务器 (非法路由器/AP) "
                       "② 在路由器开启 DHCP 防护 (DHCP Snooping)"
        })
    for e in res.get("errors", []):
        if isinstance(e, str):
            out.append({"severity": "信息", "text": e,
                        "impact": "", "action": "安装 scapy + Npcap 启用完整检测"})
    return out


def _verdict_tcp(res):
    if "error" in res:
        return res.get("error", "检测失败")
    return res.get("summary", "TCP 连接检测")


def _metrics_tcp(res):
    out = []
    total = res.get("total", 0)
    out.append(("当前连接", f"{total} 个",
                "err" if total > 800 else "warn" if total > 500 else "ok"))
    by_state = res.get("by_state", {})
    for st, label in (("ESTABLISHED", "已建立"), ("TIME_WAIT", "等待关闭")):
        if st in by_state:
            out.append((label, f"{by_state[st]} 个"))
    return out


def _issues_tcp(res):
    out = []
    for w in res.get("warnings", []):
        if isinstance(w, str):
            sev = "异常" if "临界" in w else "警告"
            out.append({"severity": sev, "text": w,
                        "impact": "可能导致连接建立失败或延迟",
                        "action": "检查占用大量连接的进程, 必要时重启"})
    return out


def _verdict_port(res):
    if "error" in res:
        return res.get("error", "检测失败")
    return res.get("summary", "端口探测")


def _metrics_port(res):
    out = []
    targets = res.get("targets", [])
    if targets:
        ok = sum(1 for t in targets if t.get("status") == "开放")
        closed = sum(1 for t in targets if t.get("status") == "关闭")
        filtered = sum(1 for t in targets if t.get("status") in ("过滤", "无响应"))
        # 开放端口颜色: 0-5 = 安全(ok), 6-15 = 偏多(warn), >15 = 偏多(err)
        # (粗略启发: 大多数服务 < 10 个开放端口, 多了通常意味着有非预期服务暴露)
        ok_level = "ok" if ok <= 5 else "warn" if ok <= 15 else "err"
        out.append(("开放端口", f"{ok} 个", ok_level))
        out.append(("关闭/过滤", f"{closed + filtered} 个", "ok"))
        out.append(("探测总数", f"{len(targets)} 个"))
        out.append(("协议", res.get("proto", "?")))
        out.append(("每目标采样", f"{res.get('probe_count', '?')} 次"))
    else:
        # 探测未执行 (例如限流拦住, 提示用户原因)
        if res.get("expanded_count"):
            out.append(("原始目标数", f"{res['expanded_count']} (被限流拦住)"))
        out.append(("协议", res.get("proto", "?")))
    return out


def _issues_port(res):
    out = []
    for issue in res.get("issues", []):
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            out.append({
                "severity": "异常" if sev == "critical" else "警告",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": "检查目标主机/防火墙配置"
            })
    return out


def _verdict_egress(res):
    if "error" in res:
        return res.get("error", "检测失败")
    issues = res.get("issues", [])
    # 只统计真实问题 (warning/critical/字符串); info 级 (VPN 占位/假网关) 不算"问题",
    # 与 determine_status 的徽章口径保持一致
    n_real = sum(
        1 for i in issues
        if isinstance(i, str)
        or (isinstance(i, dict) and i.get("severity") in ("warning", "critical"))
    )
    if n_real:
        return f"检测到多外网出口 ({n_real} 个问题)"
    return "单一真实外网出口, 正常"


def _metrics_egress(res):
    out = []
    real = [r for r in res.get("default_routes", [])
            if not _is_known_fake_gateway(r.get("gateway", ""))
            and not _is_vpn_interface(r.get("interface", ""))]
    fake = [r for r in res.get("default_routes", [])
            if _is_known_fake_gateway(r.get("gateway", ""))
            or _is_vpn_interface(r.get("interface", ""))]
    out.append(("真实默认路由", f"{len(real)} 条",
                "warn" if len(real) > 1 else "ok"))
    if fake:
        out.append(("VPN 占位路由", f"{len(fake)} 条 (已忽略)", "info"))
    pub_ips = res.get("public_ips", [])
    if pub_ips:
        out.append(("公网 IP", ", ".join(pub_ips[:2])))
    return out


def _issues_egress(res):
    """多出口 issue。
    旧版无论何种 issue 一律塞 "联系网络管理员确认多出口配置" 作为 action,
    即便是 "ZeroTier 假网关" 这种 info 级无害提示也强行弹出, 让 verdict "正常"
    的模块显得自相矛盾 (verdict 说正常, action 说联系网管)。
    现版按 type 给具体 action; info 级 (fake_gateway/vpn_adapter) 不给 action,
    让卡片只显示 "[信息]" 不附带 "建议" 行。
    """
    out = []
    type_actions = {
        "multiple_default_routes": "检查路由表, 找出非预期的多默认路由, 必要时手动指定 metric 让一条为主",
        "multiple_default": "检查路由表, 找出非预期的多默认路由, 必要时手动指定 metric 让一条为主",
        "fake_gateway_present": "",   # info 级, VPN/虚拟接口占位无需处理
        "vpn_adapter": "如非预期, 退出 VPN/加速器客户端后重测",
    }
    for issue in res.get("issues", []):
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            itype = issue.get("type", "")
            # info 级 issue 默认不给 action; 真问题才给具体建议
            default_action = "" if sev == "info" else "联系网络管理员确认多出口配置"
            action = type_actions.get(itype, default_action)
            out.append({
                "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": action,
            })
    return out


def _verdict_mtu(res):
    if "error" in res:
        return res.get("error", "检测失败")
    issues = res.get("issues", [])
    if issues:
        return f"MTU 检测: {len(issues)} 个问题"
    return "MTU 路径正常"


def _metrics_mtu(res):
    out = []
    paths = res.get("path_mtus", [])
    for p in paths:
        if p.get("error"):
            out.append((f"到 {p.get('target', '?')}", "测量失败", "warn"))
        else:
            out.append((f"到 {p.get('target', '?')}", f"MTU {p.get('path_mtu', '?')}",
                        "ok" if not p.get("fragmentation_risk") else "warn"))

    local = res.get("local_mtus", [])
    if local:
        m = local[0]
        out.append((f"本机 {_short_iface(m.get('interface', '?'), 18)}", f"MTU {m.get('mtu', '?')}",
                    "ok" if m.get("mtu", 1500) >= 1500 else "warn"))
    return out


def _issues_mtu(res):
    out = []
    for issue in res.get("issues", []):
        if isinstance(issue, str):
            out.append({
                "severity": "警告",
                "text": issue,
                "impact": "可能导致数据包分片, 降低传输效率",
                "action": "检查网络设备 MTU 配置 (PPPoE 通常 1492)"
            })
    return out


def _verdict_arp(res):
    if "error" in res:
        return res.get("error", "检测失败")
    n_total = res.get("total_entries", 0)
    n_mac = res.get("unique_macs", 0)
    issues = res.get("issues", [])
    # 只统计真实问题 (warning/critical/字符串); info 级 (静态 ARP 记录等) 不算"问题"
    n_real = sum(
        1 for i in issues
        if isinstance(i, str)
        or (isinstance(i, dict) and i.get("severity") in ("warning", "critical"))
    )
    if n_real:
        return f"ARP 表 {n_total} 条 / {n_mac} MAC, {n_real} 个问题"
    return f"ARP 表 {n_total} 条 / {n_mac} MAC, 正常"


def _metrics_arp(res):
    out = [
        ("ARP 条目", f"{res.get('total_entries', 0)} 条"),
        ("MAC 数", f"{res.get('unique_macs', 0)} 个"),
    ]
    gw = res.get("gateway_mac")
    if gw:
        out.append(("网关 MAC", gw, "ok"))
    return out


def _issues_arp(res):
    out = []
    for issue in res.get("issues", []):
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            out.append({
                "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": "检查是否存在 ARP 欺骗或网关 MAC 变更"
            })
    return out


def _verdict_ipv6(res):
    if "error" in res:
        return res.get("error", "检测失败")
    # 模块名已含 "IPv6", 结论里不再重复前缀
    return res.get("assessment", "检测结果未知")


def _metrics_ipv6(res):
    out = []
    out.append(("全局地址", "有" if res.get("has_global_ipv6") else "无",
                "ok" if res.get("has_global_ipv6") else "warn"))
    out.append(("连通性", "正常" if res.get("ipv6_connectivity") else "不可达",
                "ok" if res.get("ipv6_connectivity") else "err"))
    out.append(("IPv6 DNS", "正常" if res.get("ipv6_dns") else "失败",
                "ok" if res.get("ipv6_dns") else "warn"))
    return out


def _issues_ipv6(res):
    out = []
    # 严重级别与 determine_status 徽章口径一致: assessment 含"异常" -> 异常,
    # 含"正常" -> 信息, 其它 (不支持/仅链路本地等) -> 警告。
    # 原实现一律标"信息", 导致"徽章异常/警告、卡片里却是灰色[信息]"对不齐。
    assessment = res.get("assessment", "")
    if "异常" in assessment:
        sev = "异常"
    elif "正常" in assessment:
        sev = "信息"
    else:
        sev = "警告"
    for issue in res.get("issues", []):
        if isinstance(issue, str):
            out.append({
                "severity": sev,
                "text": issue,
                "impact": "如果不需要 IPv6 可忽略; 否则影响部分纯 IPv6 网站",
                "action": "联系运营商开通 IPv6 或检查路由器/防火墙配置"
            })
    return out


def _verdict_route(res):
    if "error" in res:
        return res.get("error", "检测失败")
    n = res.get("route_count", 0)
    issues = res.get("issues", [])
    if any(isinstance(i, dict) and i.get("severity") == "critical" for i in issues):
        return f"路由表 {n} 条, 检测到路由环路!"
    # 只统计真实问题 (warning/critical/字符串); info 级 (ZeroTier 假网关等) 不算"问题"
    n_real = sum(
        1 for i in issues
        if isinstance(i, str)
        or (isinstance(i, dict) and i.get("severity") in ("warning", "critical"))
    )
    if n_real:
        return f"路由表 {n} 条, {n_real} 个问题"
    return f"路由表 {n} 条, 正常"


def _metrics_route(res):
    out = [("路由总数", f"{res.get('route_count', 0)} 条")]
    real = [r for r in res.get("default_routes", [])
            if not _is_known_fake_gateway(r.get("gateway", ""))
            and not _is_vpn_interface(r.get("interface", ""))]
    out.append(("默认路由", f"{len(real)} 条",
                "warn" if len(real) > 1 else "ok"))
    hr = res.get("host_routes", [])
    if hr:
        out.append(("主机路由", f"{len(hr)} 条",
                    "warn" if len(hr) > 50 else "ok"))
    return out


def _issues_route(res):
    out = []
    for issue in res.get("issues", []):
        if isinstance(issue, dict):
            sev = issue.get("severity", "")
            out.append({
                "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                "text": issue.get("message", ""),
                "impact": issue.get("detail", ""),
                "action": "联系网络管理员检查路由配置"
            })
    return out


def _verdict_lan(res):
    if "error" in res:
        return res.get("error", "检测失败")
    return res.get("summary", "LAN 扫描")


def _metrics_lan(res):
    # 设备数结论里已有, 不再单独出指标卡; 只在异常时展示
    out = []
    devs = res.get("devices", [])
    unknown = sum(1 for d in devs if not d.get("vendor") and d.get("mac"))
    if unknown:
        out.append(("未知厂商设备", f"{unknown} 台", "warn"))
    return out


def _verdict_tcpstats(res):
    if "error" in res:
        return res.get("error", "检测失败")
    return res.get("summary", "TCP 传输质量")


def _metrics_tcpstats(res):
    cur = res.get("current_connections")
    cur_str = "—" if cur is None else f"{cur}"
    out = [
        ("重传率", f"{res.get('retrans_rate_pct', 0)}%",
         "err" if res.get("retrans_rate_pct", 0) >= 5 else
         "warn" if res.get("retrans_rate_pct", 0) >= 1 else "ok",
         "丢包后重发的比例; 大于 1% 链路质量偏差, 大于 5% 明显影响网速"),
        ("当前连接", cur_str, "ok",
         "本机当前的 TCP 连接总数 (实时快照, 与 TCP 连接模块采样时刻略有差异属正常)"),
    ]
    return out


def _issues_tcpstats(res):
    out = []
    rate = res.get("retrans_rate_pct", 0)
    if rate >= 1:
        out.append({
            "severity": "警告" if rate < 5 else "异常",
            "text": f"TCP 重传率 {rate}% 偏高",
            "impact": "网络存在拥塞或链路质量问题, 影响下载/视频流畅度",
            "action": "检查网络设备负载、网线质量, 排除 WiFi 干扰"
        })
    return out


def _verdict_proxy(res):
    if "error" in res:
        return res.get("error", "代理检测失败")
    s = res.get("summary", "代理检测")
    # 状态码行话转人话: "经代理 200 / 直连 200" → "经代理正常 / 直连正常"
    s = s.replace("经代理 200", "经代理正常").replace("直连 200", "直连正常")
    return s


def _metrics_proxy(res):
    wininet = res.get("wininet", {})
    probe = res.get("probe") or {}
    ep = wininet.get("proxy_endpoint") if wininet.get("proxy_enable") else None
    pac = wininet.get("auto_config_url")
    if pac:
        sys_val, sys_lvl = "PAC", "warn"
    elif ep:
        sys_val, sys_lvl = f"开 → {ep}", "warn"
    else:
        sys_val, sys_lvl = "关", "ok"
    verdict = res.get("verdict")
    avail = {"unreachable": ("不可达", "err"), "no_forward": ("拒绝转发", "err"),
             "ok_both": ("可用", "ok"), "only_proxy": ("可用(唯一通道)", "warn"),
             "both_fail": ("不可用", "warn"), "pac": ("PAC 模式", "warn"),
             "none": ("未配置", "ok")}.get(verdict, ("—", "ok"))
    if probe:
        direct = ("通" if probe.get("direct_ok") else "不通") if "direct_status" in probe else "未测"
    else:
        direct = "未测"
    vpns = res.get("vpn_adapters") or []
    hosts = res.get("hosts_check") or {}
    if hosts.get("hijacked"):
        hosts_val, hosts_lvl = f"{len(hosts['hijacked'])} 条劫持", "err"
    elif hosts.get("suspicious"):
        hosts_val, hosts_lvl = f"{len(hosts['suspicious'])} 条可疑", "warn"
    else:
        hosts_val, hosts_lvl = "干净", "ok"
    out = [
        ("系统代理", sys_val, sys_lvl),
        ("代理可用性", avail[0], avail[1]),
        ("直连对照", direct, "ok" if direct == "通" else "warn" if direct == "不通" else "ok"),
        ("VPN/虚拟网卡", f"{len(vpns)} 块" if vpns else "无", "warn" if vpns else "ok"),
        ("hosts 文件", hosts_val, hosts_lvl),
    ]
    return out


def _issues_proxy(res):
    out = []
    for issue in res.get("issues", []):
        if not isinstance(issue, dict):
            continue
        sev = {"critical": "异常", "warning": "警告"}.get(issue.get("severity"), "信息")
        # 断网根因类问题给可执行建议; 其余保持模块内 detail
        action = "查看技术细节或联系网络管理员"
        if issue.get("type") in ("proxy_unreachable", "proxy_no_forward"):
            action = "关闭系统代理 (设置 → 网络 → 代理) 或修复代理客户端"
        elif issue.get("type") == "proxy_only_path":
            action = "排障时勿直接关代理; 先确认代理用途再处理"
        elif issue.get("type") == "vpn_adapter":
            action = "如非预期, 退出 VPN/加速器客户端后重测"
        elif issue.get("type") == "hosts_hijack":
            action = ("以管理员打开 hosts (C:\\Windows\\System32\\drivers\\etc\\hosts) "
                      "删除对应行; 删完杀毒扫描复核")
        elif issue.get("type") == "hosts_suspicious":
            action = "确认非本人/合规软件所需后删除对应行"
        elif issue.get("type") == "hosts_bulk":
            action = "检查是哪个工具写入 (常见: 加速器/去广告/破解补丁), 按需清理"
        out.append({"severity": sev, "text": issue.get("message", ""),
                    "impact": issue.get("detail", ""), "action": action})
    return out


def _issues_external(res):
    """外网检测: 之前只亮徽章不出问题条目, 装维看不到处置建议 — 按段位给建议。

    丢包告警口径: 只在 TCP 不可达时触发 (TCP 可达但 ping 丢 = ICMP 限速, 不是真丢包)。
    TCP RTT 异常 (>500ms) 单独告警 (SYN 队列堆积或链路拥塞)。
    """
    out = []
    if "error" in res:
        return out
    loss = res.get("avg_loss_pct", 0) or 0
    rtt = res.get("avg_rtt_ms", 0) or 0
    tcp_ok, tcp_total = res.get("tcp_ok", 0), res.get("tcp_total", 0)
    unreachable = res.get("unreachable_count", 0) or 0
    if tcp_total and tcp_ok == 0 and unreachable:
        out.append({"severity": "异常", "text": "全部外网目标不可达",
                    "impact": "出网链路中断或被防火墙整体拦截",
                    "action": "先看网关检测与链路速率; 网关正常则查本机防火墙/代理 (跑 proxy 模块)"})
    elif unreachable:
        out.append({"severity": "警告", "text": f"{unreachable} 个外网目标不可达",
                    "impact": "部分目标不通, 可能是目标站自身问题或链路单侧劣化",
                    "action": "看技术细节里的路径追踪, 确定从哪一跳开始不通; 仅个别目标不通多为对端问题"})
    # 丢包告警口径: 与函数 docstring 一致 — 仅当 TCP 同步劣化 (有目标建连失败)
    # 时才允许升级为"异常"; TCP 全通时 ping 丢包多为 ICMP 限速, 不得直接下
    # "运营商侧故障"结论 (P0-05: 修复 loss>=5 无视 TCP 状态的误判)。
    # TCP 证据缺失 (tcp_total=0, 模块部分失败) 同样不给故障级结论。
    tcp_failed = tcp_total > 0 and tcp_ok < tcp_total
    if loss >= 5 and tcp_failed:
        out.append({"severity": "异常", "text": f"外网平均丢包 {loss}%",
                    "impact": "明显丢包: 网页卡顿、游戏掉线、视频花屏",
                    "action": "网关正常而此处丢包 → 问题更可能在运营商侧, 保留报告 (含逐跳路径) 带回报障"})
    elif loss >= 5:
        # v1.9.2 (审查修复): tcp_total=0 时不得伪造"TCP 建连正常"的表述
        if tcp_total:
            text = f"ICMP 平均丢包 {loss}% (TCP 建连正常)"
            impact = "TCP 可达但 ping 丢, 多为中间设备 ICMP 限速, 不一定是真实丢包"
        else:
            text = f"外网平均丢包 {loss}% (TCP 佐证缺失)"
            impact = "TCP 探测无数据, 可能是真实丢包也可能是 ICMP 限速, 结论存疑"
        out.append({"severity": "警告", "text": text, "impact": impact,
                    "action": "以实际应用体验为准; 若确有卡顿, 结合网关模块丢包判断段位"})
    elif loss >= 1:
        out.append({"severity": "警告", "text": f"外网平均丢包 {loss}%",
                    "impact": "轻度丢包会影响游戏/通话体验",
                    "action": "结合网关模块丢包判断段位: 网关也丢 → 更像内网问题; 网关不丢 → 更像外线问题"})
    # TCP RTT 异常告警 (TCP 握手 >500ms 说明 SYN 队列堆积或链路严重劣化)
    targets = res.get("targets") or []
    high_tcp_rtts = [t for t in targets
                     if t.get("tcp_reachable") and t.get("tcp_rtt_ms")
                     and t["tcp_rtt_ms"] > 500]
    if high_tcp_rtts:
        names = ", ".join(f"{t.get('name', '?')}({t['tcp_rtt_ms']:.0f}ms)" for t in high_tcp_rtts)
        out.append({"severity": "警告", "text": f"TCP 握手延迟异常: {names}",
                    "impact": "TCP 建连超过 500ms, 可能是中间设备 SYN 限速或链路拥塞",
                    "action": "看路径追踪逐跳延迟; 换目标重测确认是否单点问题"})
    if rtt >= 150:
        out.append({"severity": "警告", "text": f"外网平均延迟 {rtt:.0f}ms",
                    "impact": "延迟偏高, 游戏类应用会明显感觉慢",
                    "action": "看路径追踪逐跳延迟, 从哪一跳开始升高, 问题就在那一段"})
    return out


def _issues_speedtest(res):
    """测速: 宽带不达标是装维核心场景, 必须给出建议条目而非只亮警告徽章。"""
    out = []
    if "error" in res:
        return out
    down, up = res.get("download_mbps"), res.get("upload_mbps")
    if isinstance(down, (int, float)):
        if down < 1:
            out.append({"severity": "异常", "text": f"下载速率仅 {down} Mbps, 接近不可用",
                        "impact": "基本无法正常上网",
                        "action": "查链路速率是否只协商到低档位; 重启光猫; 仍低则携本报告报障"})
        elif down < 10:
            out.append({"severity": "警告", "text": f"下载速率仅 {down} Mbps, 远低于常见宽带档位",
                        "impact": "网页/视频会明显卡顿",
                        "action": "确认办理档位; 千兆环境查网线是否八芯、光猫口是否千兆口"})
    if isinstance(up, (int, float)) and up < 1:
        out.append({"severity": "警告", "text": f"上传速率仅 {up} Mbps",
                    "impact": "视频通话上传卡、网盘备份慢",
                    "action": "部分套餐上传本身限速, 对照办理档位判断是否达标"})
    grade = res.get("bufferbloat_grade") or ""
    if grade in ("D", "F"):
        out.append({"severity": "警告", "text": f"缓冲膨胀评级 {grade}",
                    "impact": "一边下载一边游戏/通话会明显变卡 (延迟暴涨)",
                    "action": "开启路由器 QoS 限速或更换路由器; 光猫路由一体机可改桥接 + 自备路由器"})
    return out


def _issues_iperf3(res):
    out = []
    if "error" in res:
        return out
    dl_err, ul_err = res.get("download_error"), res.get("upload_error")
    if dl_err or ul_err:
        sides = "、".join(s for s, e in (("下载", dl_err), ("上传", ul_err)) if e)
        out.append({"severity": "异常" if (dl_err and ul_err) else "警告",
                    "text": f"iperf3 {sides}方向测试失败",
                    "impact": "无法测得该方向的链路吞吐",
                    "action": "确认服务器端已运行 iperf3 -s 且 5201 端口放行; 单方向失败多为服务器侧单向策略或中途防火墙"})
    dl = res.get("download_mbps")
    if isinstance(dl, (int, float)) and 0 < dl < 10:
        out.append({"severity": "警告", "text": f"到服务器的下载吞吐仅 {dl} Mbps",
                    "impact": "点对点链路吞吐远低于常见水平",
                    "action": "对照 speedtest 宽带结果: 宽带正常而点对点低 → 瓶颈在中间链路或服务器侧, 保留数据带回分析"})
    if res.get("udp"):
        for side in ("download", "upload"):
            side_name = "下载" if side == "download" else "上传"
            loss = res.get(f"{side}_loss_pct")
            jit = res.get(f"{side}_jitter_ms")
            if isinstance(loss, (int, float)) and loss > 5:
                out.append({"severity": "异常", "text": f"UDP {side_name}丢包 {loss}%",
                            "impact": "语音通话/游戏会明显卡顿掉线; TCP 正常而 UDP 丢包高多为 QoS 限速或链路突发",
                            "action": "检查中间设备/运营商是否对 UDP 限速; 结合 nattype (UDP 出网) 与盯障模式复测"})
            elif isinstance(loss, (int, float)) and loss > 1:
                out.append({"severity": "警告", "text": f"UDP {side_name}丢包 {loss}%",
                            "impact": "语音质量可感知下降",
                            "action": "结合盯障模式 (--monitor) 观察是否为间歇性"})
            if isinstance(jit, (int, float)) and jit > 100:
                out.append({"severity": "警告", "text": f"UDP {side_name}抖动 {jit} ms",
                            "impact": "语音通话断续、游戏操作不跟手",
                            "action": "排查链路拥塞 (bufferbloat 模块) 与中间设备缓存策略"})
    return out


def _issues_lan(res):
    out = []
    if "error" in res:
        return out
    devs = res.get("devices") or []
    if res.get("device_count", 0) == 0 and not devs:
        out.append({"severity": "警告", "text": "未扫描到任何局域网设备",
                    "impact": "可能是权限不足、终端隔离或扫描窗口太短",
                    "action": "以管理员身份重试; 无线网络开了 AP 隔离时看不到邻居属正常现象"})
        return out
    unknown = [d for d in devs if d.get("mac") and not d.get("vendor")]
    if unknown and len(unknown) >= max(2, len(devs) // 2):
        out.append({"severity": "信息", "text": f"{len(unknown)}/{len(devs)} 台设备厂商无法识别",
                    "impact": "多为小众/贴牌设备 (智能家电常见), 不影响在线判断",
                    "action": "无需处理; 需要时可用 MAC 地址在厂商库核对"})
    return out


def _verdict_nattype(res):
    """NAT 类型 verdict。
    旧版只看 summary, 对称型时只显示第一个映射地址, 与 todo issue 块描述
    (\"42396 vs 42397\") 对不上, 用户从 overview 看 verdict 只有一个 IP, 但
    从 todo 看到两个, 会以为有数据问题。
    现版: 对称型时拼接多个映射地址 (与 _issues_nattype 口径一致)。
    """
    if "error" in res:
        return res.get("error", "NAT 类型检测失败")
    base = res.get("summary", "NAT 类型")
    beh = res.get("nat_behavior", "")
    if beh == "对称型":
        # 收集 STUN 服务器实际映射地址 (按检测顺序)
        servers = res.get("servers") or []
        mappings = []
        for s in servers:
            # 服务器记录的真实字段是 ok / mapped_addr (见 NATTypeTester.detect),
            # 此前误写成 success / mapping 导致本修复从未生效
            if isinstance(s, dict) and s.get("ok") and s.get("mapped_addr"):
                m = s["mapped_addr"]
                if m not in mappings:
                    mappings.append(m)
        if len(mappings) >= 2:
            return f"{base} ({mappings[0]} vs {mappings[1]})"
    return base


def _metrics_nattype(res):
    beh = res.get("nat_behavior", "—")
    blocked = bool(res.get("udp_blocked"))
    ipm = res.get("ip_match")
    if blocked:
        beh_lvl = "err"
    elif beh == "对称型":
        beh_lvl = "warn"
    else:
        beh_lvl = "ok"
    if ipm is False:
        match_val, match_lvl = "不一致", "warn"
    elif ipm:
        match_val, match_lvl = "一致", "ok"
    else:
        match_val, match_lvl = "—", "ok"
    out = [
        ("映射行为", beh, beh_lvl),
        ("UDP 出网", "受阻" if blocked else "正常", "err" if blocked else "ok"),
        ("出口一致性", match_val, match_lvl),
        ("本机内网IP", res.get("local_lan_ip") or "—", "ok"),
    ]
    cone = res.get("cone_type")
    if cone and cone not in ("—",):
        out.insert(1, ("锥形细分", cone, "ok"))
    return out


def _issues_nattype(res):
    out = []
    for issue in res.get("issues", []):
        if not isinstance(issue, dict):
            continue
        sev = {"critical": "异常", "warning": "警告"}.get(issue.get("severity"), "信息")
        action = {
            "udp_blocked": "检查路由器 UDP 出站限制与本机防火墙; 对比 dns 模块 (TCP 53) 是否正常",
            "symmetric": "对称型下 P2P 直连难属预期; 游戏/语音改用中继模式或联系运营商",
            "egress_mismatch": "结合多出口 (egress) 与代理检测 (proxy) 判断哪个出口在分流量",
        }.get(issue.get("type"), "查看技术细节")
        out.append({"severity": sev, "text": issue.get("message", ""),
                    "impact": issue.get("detail", ""), "action": action})
    return out


def _verdict_web(res):
    if "error" in res:
        return res.get("error", "网页体检失败")
    return res.get("summary", "网页体检")


def _metrics_web(res):
    ok, total = res.get("ok_count", 0), res.get("total_count", 0)
    ttfb, dns, tls = res.get("avg_ttfb_ms"), res.get("avg_dns_ms"), res.get("avg_tls_ms")
    cert = res.get("min_cert_days")

    def lvl(v, warn, err):
        return ("err" if v >= err else "warn" if v >= warn else "ok") if v is not None else "ok"

    return [
        ("目标可达", f"{ok}/{total}", "err" if ok == 0 else "warn" if ok < total else "ok"),
        ("平均首字节", f"{ttfb} ms" if ttfb is not None else "—", lvl(ttfb, 500, 2000)),
        ("平均 DNS", f"{dns} ms" if dns is not None else "—", lvl(dns, 200, 10**9)),
        ("平均 TLS", f"{tls} ms" if tls is not None else "—", lvl(tls, 500, 10**9)),
        ("证书最短剩余", f"{cert} 天" if cert is not None else "—",
         "err" if cert is not None and cert < 7 else
         "warn" if cert is not None and cert < 30 else "ok"),
    ]


def _issues_web(res):
    # 断层定位: 每类失败给指向既有模块的可执行建议
    actions = {
        "dns_fail": "运行 dns 模块定位解析链路",
        "tcp_fail": "运行 port 模块探测 80/443, 检查防火墙出站",
        "tls_cert_fail": "核对系统时间; 检查是否存在 HTTPS 中间盒/企业解密",
        "tls_fail": "检查中间盒拦截或 TLS 版本兼容性",
        "http_fail": "结合外网检测 (external) 判断链路, 或目标站点本身故障",
        "ttfb_slow": "DNS/TCP/TLS 均正常时为服务端或链路慢, 结合测速与 route 判断",
        "cert_expire": "联系站点管理员续期证书",
        "cert_soon": "关注证书续期",
    }
    impacts = {
        "tls_cert_fail": "疑似中间人/企业 HTTPS 解密或系统时间错误, 浏览器会报证书错误",
        "dns_fail": "域名无法解析, 所有依赖该域名的服务不可用",
        "tcp_fail": "传输层不通: 防火墙拦截或目标端口未开放",
    }
    out = []
    for issue in res.get("issues", []):
        if not isinstance(issue, dict):
            continue
        sev = {"critical": "异常", "warning": "警告"}.get(issue.get("severity"), "信息")
        t = issue.get("type", "")
        out.append({"severity": sev, "text": issue.get("message", ""),
                    "impact": impacts.get(t, issue.get("detail", "")),
                    "action": actions.get(t, "查看技术细节")})
    return out


def _verdict_tcpcc(res):
    """TCP 并发 verdict。
    原版只用 summary, 不反映高并发下的 P95 延迟恶化 (800/1600 级常见)
    现版: 在 summary 基础上追加 P95 异常提示, 让装维一眼看到高并发吃力
    """
    if "error" in res:
        return res.get("error", "TCP 并发测试失败")
    base = res.get("summary", "TCP 并发")
    # 检查各级别 P95: 凡是最后通过的级别 P95 > 500ms 视为"高并发吃力"
    levels = res.get("levels") or []
    high_p95_levels = []
    for r in levels:
        if (r.get("success_rate", 0) >= 90
                and isinstance(r.get("p95_ms"), (int, float))
                and r["p95_ms"] > 500):
            high_p95_levels.append((r["level"], r["p95_ms"]))
    if high_p95_levels:
        max_lvl, max_p95 = max(high_p95_levels, key=lambda x: x[0])
        return (f"{base}; 高并发时新建连接明显变慢 "
                f"(并发 ≥{max_lvl} 时, 95% 的连接需 {max_p95:.0f}ms 才建立, "
                f"理想应在 500ms 内)")
    return base


def _metrics_tcpcc(res):
    n = res.get("max_sustained", 0)
    capped = bool(res.get("capped")) and n
    shown = f"≥{n}" if capped else str(n)
    levels = res.get("levels") or []
    last_ok = None
    for r in levels:
        if r.get("attempted") and r.get("success_rate", 0) >= 90 and r.get("p95_ms"):
            last_ok = r
    base = res.get("local_baseline") or {}
    base_ok = bool(base) and base.get("success_rate", 0) >= 90
    bottleneck = res.get("bottleneck")
    # capped (全级别通过) = 容量至少 N, 不按 N 的大小判色
    n_lvl = "ok" if capped else ("err" if n < 512 else "warn" if n < 1024 else "ok")
    out = [
        ("最大并发", shown, n_lvl),
        ("半数建连耗时", f"{last_ok['p50_ms']} ms" if last_ok else "—", "ok",
         "一半连接在此耗时内完成"),
        ("95%建连耗时", f"{last_ok['p95_ms']} ms" if last_ok else "—",
         "warn" if last_ok and last_ok["p95_ms"] > 500 else "ok",
         "95% 的连接慢于此值即偏慢"),
        ("峰值建连", f"{res.get('peak_cps', 0):.0f} /s", "ok"),
        ("本机对照",
         f"{base.get('level')} 并发{'通过' if base_ok else '受限' }" if base else "—",
         "ok" if base_ok or not base else "warn"),
    ]
    if bottleneck in ("本机", "网络/NAT"):
        out.append(("瓶颈位置", bottleneck, "warn" if bottleneck == "本机" else "ok"))
    return out


def _issues_tcpcc(res):
    actions = {
        "low_concurrency": "检查路由器/光猫 NAT 并发会话数规格; 对照本机回环结果区分本机/网络瓶颈",
        "fail_mode": "超时为主→NAT 表满, 考虑升级设备或减少长连接设备; 拒绝为主→换 --tcpcc-target 复测",
        "local_bottleneck": "排查安全软件/终端管控软件的连接数限制; 对照资源监视器确认",
        "path_bottleneck": "重启网关; 核实设备 NAT 规格是否与办理带宽匹配",
        "high_p95": "升级路由器 NAT 规格/换更高速设备; 检查运营商侧是否有连接数/QoS 限制",
    }
    out = []
    for issue in res.get("issues", []):
        if not isinstance(issue, dict):
            continue
        sev = {"critical": "异常", "warning": "警告"}.get(issue.get("severity"), "信息")
        out.append({"severity": sev, "text": issue.get("message", ""),
                    "impact": issue.get("detail", ""),
                    "action": actions.get(issue.get("type"), "查看技术细节")})
    return out


# 通用兜底: 没专门配置的模块, 用 summary + 2-3 个简单指标
def _generic_verdict(res):
    if "error" in res:
        return res.get("error", "检测失败")
    return res.get("summary", "检测完成")


def _generic_metrics(res):
    """从 result 顶层挑 2-3 个数字字段做指标, 没有就空。"""
    out = []
    for k, v in res.items():
        if k in ("summary", "issues", "timestamp", "method", "assessment",
                 "error", "warnings"):
            continue
        if isinstance(v, (int, float)) and v:
            out.append((HEADER_MAP.get(k, k), str(v)))
            if len(out) >= 3:
                break
    return out


def _generic_issues(res):
    out = []
    issues = res.get("issues", [])
    if isinstance(issues, list):
        for issue in issues:
            if isinstance(issue, str):
                out.append({"severity": "警告", "text": issue,
                            "impact": "",
                            "action": "按结论提示现场排查; 无法定位时保留本报告 (HTML+JSON) 带回支撑分析"})
            elif isinstance(issue, dict):
                sev = issue.get("severity", "")
                out.append({
                    "severity": "异常" if sev == "critical" else "警告" if sev == "warning" else "信息",
                    "text": issue.get("message", ""),
                    "impact": issue.get("detail", ""),
                    "action": "查看该模块技术细节; 现场无法处理时保留本报告带回会诊"
                })
    for w in res.get("warnings", []):
        if isinstance(w, str) and not any(i.get("text") == w for i in out):
            out.append({"severity": "警告", "text": w,
                        "impact": "",
                        "action": "按结论提示现场排查; 无法定位时保留本报告 (HTML+JSON) 带回支撑分析"})
    return out


# 模块配置映射: 没列的模块走通用规则
MODULE_PRESENTATION = {
    "dhcp":       {"verdict_fn": _verdict_dhcp,       "metrics_fn": _metrics_dhcp,
                   "issues_fn": _issues_dhcp},
    "gateway":    {"verdict_fn": _verdict_gateway,    "metrics_fn": _metrics_gateway,
                   "issues_fn": _issues_gateway,
                   "tech_keys": ["ping"]},
    "loop":       {"verdict_fn": _verdict_loop,       "metrics_fn": _metrics_loop,
                   "issues_fn": _issues_loop,
                   "tech_keys": ["arp_entries"]},
    "external":   {"verdict_fn": _verdict_external,   "metrics_fn": _metrics_external,
                   "issues_fn": _issues_external,
                   "tech_keys": ["targets", "traceroute"]},
    "linkspeed":  {"verdict_fn": _verdict_linkspeed,  "metrics_fn": _metrics_linkspeed,
                   "issues_fn": _issues_linkspeed,
                   "tech_keys": ["adapters"]},
    "wifi":       {"verdict_fn": _verdict_wifi,       "metrics_fn": _metrics_wifi,
                   "issues_fn": _issues_wifi,
                   "tech_keys": ["networks", "channel_analysis"]},
    "tcp":        {"verdict_fn": _verdict_tcp,        "metrics_fn": _metrics_tcp,
                   "issues_fn": _issues_tcp,
                   "tech_keys": ["top_processes"]},
    "port":       {"verdict_fn": _verdict_port,       "metrics_fn": _metrics_port,
                   "issues_fn": _issues_port,
                   "tech_keys": ["targets"]},
    "egress":     {"verdict_fn": _verdict_egress,     "metrics_fn": _metrics_egress,
                   "issues_fn": _issues_egress,
                   "tech_keys": ["default_routes", "egress_status"]},
    "dns":        {"verdict_fn": _verdict_dns,        "metrics_fn": _metrics_dns,
                   "issues_fn": _issues_dns,
                   "tech_keys": ["detail", "system_dns"]},
    "mtu":        {"verdict_fn": _verdict_mtu,        "metrics_fn": _metrics_mtu,
                   "issues_fn": _issues_mtu,
                   "tech_keys": ["path_mtus", "local_mtus"]},
    "arp":        {"verdict_fn": _verdict_arp,        "metrics_fn": _metrics_arp,
                   "issues_fn": _issues_arp,
                   "tech_keys": ["entries", "multi_ip_macs"]},
    "bufferbloat":{"verdict_fn": _verdict_bufferbloat,"metrics_fn": _metrics_bufferbloat,
                   "issues_fn": _issues_bufferbloat},
    "ipv6":       {"verdict_fn": _verdict_ipv6,       "metrics_fn": _metrics_ipv6,
                   "issues_fn": _issues_ipv6,
                   "tech_keys": ["local_ipv6"]},
    "route":      {"verdict_fn": _verdict_route,      "metrics_fn": _metrics_route,
                   "issues_fn": _issues_route,
                   "tech_keys": ["routes"]},
    "speedtest":  {"verdict_fn": _verdict_speedtest,  "metrics_fn": _metrics_speedtest,
                   "issues_fn": _issues_speedtest,
                   "tech_keys": ["speedtest", "http", "up_result"]},
    "iperf3":     {"verdict_fn": _verdict_iperf3,     "metrics_fn": _metrics_iperf3,
                   "issues_fn": _issues_iperf3,
                   "tech_keys": ["download_intervals_mbps", "upload_intervals_mbps"]},
    "lan":        {"verdict_fn": _verdict_lan,        "metrics_fn": _metrics_lan,
                   "issues_fn": _issues_lan,
                   "tech_keys": ["devices"]},
    "tcpstats":   {"verdict_fn": _verdict_tcpstats,   "metrics_fn": _metrics_tcpstats,
                   "issues_fn": _issues_tcpstats},
    "proxy":      {"verdict_fn": _verdict_proxy,      "metrics_fn": _metrics_proxy,
                   "issues_fn": _issues_proxy,
                   "tech_keys": ["wininet", "winhttp", "env_proxies", "vpn_adapters",
                                 "hosts_check", "probe"]},
    "nattype":    {"verdict_fn": _verdict_nattype,    "metrics_fn": _metrics_nattype,
                   "issues_fn": _issues_nattype,
                   "tech_keys": ["servers"]},
    "web":        {"verdict_fn": _verdict_web,        "metrics_fn": _metrics_web,
                   "issues_fn": _issues_web,
                   "tech_keys": ["targets", "redirect_chain"]},
    "tcpcc":      {"verdict_fn": _verdict_tcpcc,      "metrics_fn": _metrics_tcpcc,
                   "issues_fn": _issues_tcpcc,
                   "tech_keys": ["levels", "target_candidates", "local_baseline",
                                 "established_before", "established_after"]},
}


# ── 装维可读性: 模块说明 + 指标术语解释 ──
# 报告受众是装维人员: 每个模块卡片配一句"这是测什么的、结果怎么看",
# 行话指标 (TTFB/P95/CPS/NAT 类型…) 配通俗解释。集中两张表, 渲染层注入。
MODULE_EXPLAINS = {
    "linkspeed": "看电脑与网关之间的通道协商到了多高速率 (网线芯数/水晶头/WiFi 档位决定)。千兆宽带只协商到百兆是最常见的不达标原因。",
    "dhcp": "检查 IP 地址由谁分配。内网出现多台 DHCP 服务器 (常见于私接的路由器) 会导致上网时好时坏、网段错乱。",
    "lan": "清点当前局域网在线设备 (基于 ARP 表), 可发现陌生设备或私接的路由器/交换机。",
    "wifi": "扫描周边 WiFi 的信道占用并推荐最空闲信道。信道拥挤 = WiFi 慢但宽带本身正常, 换信道即可改善。",
    "ipv6": "检查新一代网络地址 (IPv6) 是否开通可用。部分运营商业务与测评依赖它, 缺失属资源配置问题非故障。",
    "egress": "检查是否同时存在多条上网出口 (如网线+VPN/加速器并行)。流量走错出口会出现『测速正常但某个软件不通』。",
    "speedtest": "实测下载/上传速率并推算宽带档位。实测明显低于办理档位 = 线路或设备有问题, 是装维核心验收项。",
    "bufferbloat": "测『一边满速下载、一边游戏/通话』时延会不会暴涨。评级差说明路由器缓存策略差, 表现为下载时全家卡。",
    "iperf3": "到指定服务器点对点测吞吐 (内网/专线验收用), 测的是链路吞吐, 与互联网宽带测速是两回事。UDP 模式 (--iperf3-udp) 改测抖动/丢包 — 语音/游戏质量的关键指标。",
    "tcpcc": "压测整条通路同时能保持多少条 TCP 连接 (光猫/路由器的 NAT 会话表容量)。数值低 = 设备一连多就掉线、网页资源加载不全。",
    "gateway": "Ping 网关 (光猫/路由器), 反映『本机 ↔ 网关』这一段的质量。这里丢包/高延迟说明问题在内网 (网线/WiFi/路由器), 无需找运营商。",
    "external": "Ping 多个外网目标并逐跳追踪路径, 定位问题出在哪一段: 内网侧、运营商侧还是目标网站侧。",
    "dns": "检查域名解析 (DNS) 的速度与结果正确性, 并识别 DNS 劫持。典型症状: 网页打不开但 QQ/微信正常。",
    "web": "把『打开一个网页』拆成 域名解析→TCP 建连→加密握手→首字节 四段分别计时, 哪一段失败/慢一目了然, 不再靠猜。",
    "arp": "排查 ARP 冲突与 ARP 欺骗 (内网攻击/设备故障), 表现为网速慢、频繁掉线、页面被插广告。",
    "loop": "排查内网环路/广播风暴 (常见于路由器 LAN 口误接回环线), 表现为全网突然极慢甚至断网。",
    "tcp": "统计本机当前 TCP 连接的数量、状态与占用程序。连接数爆表时新连接建立不上, 表现为『什么都打不开』。",
    "port": "探测指定地址的端口是否可达、响应多快, 用于验证服务是否在线、防火墙是否放行。",
    "route": "检查系统路由表有无环路/异常网关等会导致『网关能 ping 通但上不了网』的配置问题。",
    "tcpstats": "看系统 TCP 层的累计质量统计: 重传率高 = 链路实际在丢包 (干扰/劣化), 即使 ping 看不出来。",
    "mtu": "探测链路允许的最大包尺寸。不匹配的典型症状: 网页打得开但图片/验证码加载不出、VPN 连得上但传不了数据。",
    "proxy": "清点系统里的代理/加速器设置、hosts 文件劫持并实测代理是否还能用。『开了代理但代理已失效』『hosts 被改』都是打不开网页的高频根因。",
    "nattype": "判定出口 NAT 类型 (锥形/对称) 并检查 UDP 能否出网, 直接影响游戏联机、视频通话能否直连; 对称型属运营商侧网络结构, 现场无法改变。",
}

# 指标术语解释: {模块: {指标名: 通俗解释}}。present 层按 (key, label) 注入,
# 模块自带 hint (如 ARP) 优先, 都没有才回落"超过阈值"。
METRIC_HINTS = {
    "gateway": {
        "平均延迟": "本机到网关的往返时间, 反映内网段质量",
        "丢包率": "内网丢包, 超过 1% 就会影响游戏/通话",
        "抖动": "延迟的波动幅度, 越大越卡",
    },
    "external": {
        "平均延迟": "到外网目标的往返时间",
        "平均丢包": "外网方向丢包; 网关正常而这里丢 = 问题在运营商侧或对端",
        "TCP 可达": "直接测目标端口连通性 (部分站点禁 ping 但 TCP 正常, 以此为准)",
        "禁拼目标": "对方防火墙禁 ping, 不算故障",
        "不可达目标": "ping 与 TCP 均不通的目标",
    },
    "speedtest": {
        "下载": "实测下载速率; < 10 Mbps 警告, < 1 Mbps 异常 (千兆期望下应达 800+ Mbps, 百兆期望下应达 80+ Mbps)",
        "上传": "实测上传速率; < 5 Mbps 警告, < 1 Mbps 异常",
        "预估宽带": "按实测速率推算的宽带档位",
        "缓冲膨胀": "满载时的延迟增加量, 大于 100ms 会让游戏/通话明显变卡",
    },
    "bufferbloat": {
        "空闲延迟": "没人用网时的基础延迟",
        "负载延迟": "满速下载时的延迟",
        "延迟增加": "负载与空闲的差值, 越小越好",
        "评级": "A 最好, F 最差",
    },
    "web": {
        "平均 DNS": "把域名解析成 IP 的耗时",
        "平均 TLS": "加密握手耗时, 走代理/加速器会明显变大",
        "平均首字节": "发出请求到收到响应第一个字节的时间, 反映服务端+链路快慢",
        "证书最短剩余": "网站数字证书的剩余有效期, 过期后浏览器会报『不安全』",
        "重定向次数": "跳转几次才到最终页面",
    },
    "tcpcc": {
        "最大并发": "同时保持的连接数上限; 低于 1024 的光猫/路由器容易设备一连多就掉线",
        "建连 P50": "一半的连接在此时间内完成建立",
        "建连 P95": "95% 的连接在此时间内完成, 数值大说明高并发下很吃力",
        "峰值建连": "每秒能新建的连接数 (CPS)",
        "本机对照": "同样并发在本机内部重测; 对照通过 = 瓶颈在网络侧而非这台电脑",
    },
    "nattype": {
        "映射行为": "锥形 = 对外用同一端口 (P2P 直连友好); 对称型 = 每个目标不同端口 (打洞难, 多需中继)",
        "UDP 出网": "游戏/语音常用的 UDP 包能否出去, 受阻则联机/通话不通",
        "出口一致性": "UDP 出口与网页出口是否同一个 IP; 不一致 = 多出口或走了代理",
        "映射地址": "运营商网络侧看到的本机地址",
    },
    "proxy": {
        "系统代理": "浏览器等大多数软件共用的代理开关 (改它会全局生效)",
        "代理可用性": "代理服务器是否还活着、能否转发",
        "直连对照": "不走代理直接访问同样的网站是否正常",
        "VPN/虚拟网卡": "ZeroTier/加速器等虚拟网卡; 存在时各模块测的是隧道链路而非物理宽带",
    },
    "tcpstats": {
        "重传率": "丢包后重发的比例; 大于 1% 链路质量偏差, 大于 5% 明显影响网速",
        "当前连接": "本机当前的 TCP 连接总数",
    },
    "iperf3": {
        "下载抖动": "延迟波动幅度, 语音通话要求 <30ms",
        "上传抖动": "延迟波动幅度, 语音通话要求 <30ms",
        "下载UDP丢包": "语音/游戏包丢失率, 大于 1% 人耳可感知",
        "上传UDP丢包": "语音/游戏包丢失率, 大于 1% 人耳可感知",
    },
    "linkspeed": {
        "网卡错误": "自开机累计值, 重启清零; 换线后复测对比才有意义",
    },
}


def _present_module(key, raw_result, status):
    """把单个模块的 raw result 转成客户视图。"""
    pres = MODULE_PRESENTATION.get(key, {})
    verdict_fn = pres.get("verdict_fn", _generic_verdict)
    metrics_fn = pres.get("metrics_fn", _generic_metrics)
    issues_fn = pres.get("issues_fn", _generic_issues)

    name = MODULE_MAP.get(key, (key, key))[0]
    verdict = verdict_fn(raw_result) if raw_result else "未检测"

    # 超时/失败时 verdict_fn 可能把 {"error": ...} 当空数据解读, 给出与故障无关的
    # 结论文案 (实测: linkspeed 超时 → "检测到 0 个适配器, 无在线网卡";
    # wifi 超时 → "发现 0 个 WiFi 网络, 干扰等级: 正常")。这类文案会误导装维
    # 去查网卡/WiFi, 而真实原因只是这一个模块没跑完, 故一律以 error 原文为准。
    if (status in ("超时", "错误") and isinstance(raw_result, dict)
            and raw_result.get("error")):
        verdict = str(raw_result["error"])

    # 指标: 兼容老格式 (label, value) 和新格式 (label, value, level) / (label, value, level, hint)
    raw_metrics = metrics_fn(raw_result) if raw_result else []
    metrics = []
    for m in raw_metrics:
        if len(m) == 4:
            metrics.append({"label": m[0], "value": m[1], "level": m[2] or "ok", "hint": m[3] or ""})
        elif len(m) == 3:
            metrics.append({"label": m[0], "value": m[1], "level": m[2] or "ok", "hint": ""})
        else:
            metrics.append({"label": m[0], "value": m[1], "level": "ok", "hint": ""})

    # 术语解释 (装维视角): 集中表按 (模块, 指标名) 注入; 已有 hint 不覆盖,
    # 注入后仍为空的非 ok 指标才回落到"超过阈值"提示
    for m in metrics:
        if not m["hint"]:
            m["hint"] = METRIC_HINTS.get(key, {}).get(m["label"], "")

    # 给关键指标补阈值提示
    for m in metrics:
        # 已经显式给了 level 的不覆盖 hint
        if m["level"] != "ok" and not m["hint"]:
            m["hint"] = ("未达到正常标准" if m["level"] == "err"
                          else "轻微超出正常范围")

    # ARP 模块专用: 给"ARP 条目"和"MAC 数"加 hint, 让用户一眼看出
    # MAC 数 < ARP 条目 是因为过滤了广播/组播/协议保留 MAC (避免
    # "多 IP 同 MAC"误报)。统计口径不直观, 必须用 hint 解释。
    if key == "arp" and raw_result:
        entries = raw_result.get("entries") or []
        total_entries = raw_result.get("total_entries", 0)
        unique_macs = raw_result.get("unique_macs", 0)
        reserved_macs = len({
            e["mac"] for e in entries
            if e.get("mac") and not _is_valid_unicast_mac(e["mac"])
        })
        for m in metrics:
            if m["label"] == "ARP 条目":
                if reserved_macs:
                    m["hint"] = (f"含 {reserved_macs} 个协议保留 MAC "
                                 f"(广播/组播, 见技术细节)")
                else:
                    m["hint"] = "全部为有效单播 MAC"
            elif m["label"] == "MAC 数":
                if total_entries != unique_macs:
                    m["hint"] = "已扣除协议保留 MAC, 仅保留单播"
                else:
                    m["hint"] = "全部为单播 MAC"

    # ARP 模块卡片顶部追加一条自解释 info, 告诉用户"MAC 数 < ARP 条目"
    # 不是丢数据, 是过滤协议保留 MAC 的统计口径。
    # 注意: 必须放在 issues_fn(...) 之前, 否则会被覆盖。
    arp_auto_inject = None
    if key == "arp" and raw_result:
        total_entries = raw_result.get("total_entries", 0)
        unique_macs = raw_result.get("unique_macs", 0)
        if total_entries != unique_macs:
            arp_auto_inject = {
                "severity": "信息",
                "text": (f"MAC 数 ({unique_macs}) 少于 ARP 条目 ({total_entries}), "
                         f"差额已扣除广播/组播/协议保留 MAC (避免误报 '多 IP 同 MAC')"),
                "impact": "",
                "action": "",
            }

    issues = issues_fn(raw_result) if raw_result else []
    if arp_auto_inject:
        # 插到列表首位, 让这条解释最先被看到
        issues = [arp_auto_inject] + list(issues)

    # 检查是否有实际的技术细节数据（而非仅检查配置）
    has_tech = False
    if pres.get("tech_keys") and raw_result:
        for k in pres["tech_keys"]:
            v = raw_result.get(k)
            if v:
                if isinstance(v, list) and v:
                    has_tech = True
                    break
                elif isinstance(v, dict) and v:
                    has_tech = True
                    break
                elif isinstance(v, str) and v:
                    has_tech = True
                    break

    return {
        "key": key,
        "name": name,
        "status": status,
        "verdict": verdict,
        "key_metrics": metrics,
        "issues": issues,
        "has_tech_details": has_tech,
        "raw": raw_result or {},   # 客户报告不展示, JSON 报告用
    }


# 健康评分: 0-100
# 异常-20, 错误-30, 警告-5, 未检测-2, 扣到 0 为止
HEALTH_GRADE_TABLE = [
    (90, "A", "优秀"),
    (75, "B", "良好"),
    (60, "C", "一般"),
    (40, "D", "欠佳"),
    (0,  "F", "严重"),
]

def compute_health_score(counts, text_counts=None):
    """根据模块状态计数算健康分和等级。

    counts: 扣分口径的 {"完成": N, "警告": N, "异常": N, "错误": N, ...}。
            调用方应先排除评分豁免模块 (iperf3/ipv6/proxy/nattype)。
    text_counts: 文案口径的计数 (默认 = counts)。传含豁免模块的全量计数时,
            verdict 文案与"检测结果一览"徽章/统计卡数字保持一致 —
            豁免模块不扣分, 但客户看得到它的红色徽章, 文案少报会自相矛盾。

    评分口径: 异常 -20 / 错误 -30 (硬故障), 警告 -2 (仅提示, 不压垮总分),
    超时 -10 (检测未跑完, 结果不可信, 严重程度介于警告与异常之间),
    未检测不扣分 (环境缺测如无 WiFi 网卡不应被记过)。
    「超时」必须扣分: 超时模块会被 _issues_* 登记成 severity="异常" 的 issue,
    若评分不认它, 就会出现"23 个模块全超时 → 100 分 A 级 '网络良好, 无问题'"、
    而同一份报告的待办清单与详细结果却说有问题的自相矛盾。
    verdict 口径: 按模块状态计数 — 按实际 issue 条目计数会把同一模块的
    多条 issue 算成多项异常, 与一览徽章数对不上。
    """
    score = 100
    score -= counts.get("异常", 0) * 20
    score -= counts.get("错误", 0) * 30
    score -= counts.get("警告", 0) * 2
    score -= counts.get("超时", 0) * 10
    score = max(0, min(100, score))

    tc = text_counts if text_counts is not None else counts
    err_mod = tc.get("异常", 0) + tc.get("错误", 0)
    warn_mod = tc.get("警告", 0)
    timeout_mod = tc.get("超时", 0)
    for threshold, grade, label in HEALTH_GRADE_TABLE:
        if score >= threshold:
            if err_mod == 0 and warn_mod == 0 and timeout_mod == 0:
                verdict = "网络良好, 无问题"
            elif err_mod > 0:
                # 超时另计, 不与异常混为一谈: 前者是"没测出来", 后者是"测出来有问题"
                extra = f" / {timeout_mod} 个未完成检测" if timeout_mod else ""
                verdict = (f"{err_mod + warn_mod + timeout_mod} 个模块需关注 "
                           f"(含 {err_mod} 个异常{extra})")
            elif warn_mod > 0 and timeout_mod > 0:
                verdict = (f"{warn_mod + timeout_mod} 个模块需关注 "
                           f"(含 {warn_mod} 个警告 / {timeout_mod} 个未完成检测)")
            elif timeout_mod > 0:
                verdict = f"{timeout_mod} 个模块未完成检测, 本次结果仅供参考"
            else:
                verdict = f"{warn_mod} 个模块提示警告"
            return {
                "score": score,
                "grade": grade,
                "label": label,
                "verdict": f"{label} · {verdict}",
            }
    return {"score": 0, "grade": "F", "label": "严重",
            "verdict": "严重 · 存在多项严重问题"}


def build_report(rule_filter=None, diagnosis=None):
    """基于最近一次诊断运行 (LAST_RUN) 构造完整报告数据结构 (双视图)。

    rule_filter: 场景 profile id (可选, v1.6.1)。透传根因分析 — 导出报告的
                 root_causes 与场景完成屏同一规则集; None = 全规则 (老行为)。
    diagnosis:   预构建的根因 dict (DiagnosisReport.to_dict(), v1.6.1)。
                 场景路径把完成屏那份诊断传进来, 报告复用同一结果,
                 不再整轮重跑规则评估 (审查 #8); None = 内部自建。

    返回结构 (供 render_report_html_customer / render_report_json 使用):
      {
        "app": ..., "version": ..., "generated_at": ...,
        "schema_version": SCHEMA_VERSION,  # 阶段 C · v1.3.0 新增 (C6); v1.9.0 起 1.2.0
        "system": {local_ip, gateway, dns, public_ip, asn, geo, ipv6_public_ip},
        "health": {score, grade, label, verdict, counts},
        "summary": {key: status},  # 各模块状态 (老格式, 兼容)
        "counts": {完成: N, 警告: N, ...},  # 状态计数
        "diagnosis": {  # 阶段 C · v1.3.0 新增 (C5+C6)
          "root_causes": [...],  # RootCause.to_dict() 列表
          "overall_confidence": 0.85,
          "rules_evaluated": 6,
          "rules_fired": 2,
        },
        "modules": [  # 客户视图模块列表
          {key, name, status, verdict, key_metrics, issues, has_tech_details, raw},
          ...
        ],
        "tech": {  # 技术视图, 仅 JSON 报告用
          "raw_results": {...},   # 原 LAST_RUN["results"] 全量
          "module_keys": [...],
          "thresholds": THRESHOLDS,
        }
      }
    """
    if not LAST_RUN:
        return None
    run = LAST_RUN

    # 状态计数 (按模块状态)
    # 豁免模块不参与扣分: iperf3(未配置不是故障), ipv6(可选), proxy/VPN(环境特性), nattype(运营商侧)
    EXEMPT_MODULES = {"iperf3", "ipv6", "proxy", "nattype"}
    counts = {}          # 扣分口径: 不含豁免模块
    all_counts = {}      # 文案口径: 全部模块 (与"检测结果一览"的徽章一致)
    exempt_count = 0
    for key, st in run["status"].items():
        all_counts[st] = all_counts.get(st, 0) + 1
        if key in EXEMPT_MODULES:
            exempt_count += 1
            continue  # 豁免模块不计入扣分
        counts[st] = counts.get(st, 0) + 1

    # 客户视图模块列表
    modules = []
    for key in run["keys"]:
        name = MODULE_MAP.get(key, (key, key))[0]
        res = run["results"].get(key, {})
        status = run["status"].get(key, "未检测")
        # iperf3 未配置服务器不是故障: 显示"未检测"而非"错误",
        # 避免客户看到红色错误误以为网络有问题
        if (key == "iperf3" and "error" in res
                and "未指定" in str(res.get("error", ""))):
            status = "未检测"
        modules.append(_present_module(key, res, status))

    # 健康分: 扣分只用 counts (不含豁免, 可选/环境/运营商问题不压总分);
    # verdict 文案用 all_counts (含豁免, 与一览徽章、统计卡的数字一致 —
    # 豁免模块的异常客户同样看得到, 文案少报会造成"一览 2 个红而这里说 1 个"的矛盾)。
    health = compute_health_score(
        counts, text_counts=all_counts,
    )

    # v1.6.1: 优先复用调用方传入的诊断 (场景路径同源), 否则内部构建
    if diagnosis is None:
        diagnosis = _build_diagnosis_with_evidence(
            run["results"], rule_filter=rule_filter,
            evidence_by_module=run.get("evidence")).to_dict()

    return {
        "app": run["app"],
        "version": run["version"],
        "schema_version": SCHEMA_VERSION,   # v1.9.0: evidence 升一等结构 (Schema v1.2)
        "generated_at": run["generated_at"],
        "system": run["system"],
        "health": health,
        "counts": counts,
        "exempt_count": exempt_count,        # 评分豁免的模块数 (iperf3/ipv6/proxy/nattype)
        "summary": {m["key"]: m["status"] for m in modules},
        # v1.5.0: 检测耗时 / 检测范围 — 只跑部分模块时健康分容易被误读为
        # "全部 23 项正常", Hero 必须显式给出覆盖比例
        "duration_ms": int(run.get("duration_ms") or 0),
        # v1.5.3: 去重计数 — 重复键会使 sel > tot, Hero 反而显示「全覆盖」
        "selected_modules": len(set(run.get("keys") or [])),
        "total_modules": int(run.get("total_modules") or len(MODULE_MAP)),
        # 阶段 C · v1.3.0 新增 (C5+C6): 根因分析报告
        # 6 条内置规则 (DNS/WAN/WiFi/Bufferbloat/网关丢包/NAT) 跨模块证据聚合.
        # v1.5.0: 额外挂 supports/excludes 证据链 (见 _enrich_diagnosis_evidence)
        # v1.6.1: rule_filter 透传 — 场景导出的报告与完成屏同规则集,
        # 不再夹带屏幕上有意隐藏的根因 (如 gaming 报告里的 wifi_weak)
        "diagnosis": diagnosis,
        "modules": modules,
        "tech": {
            "raw_results": run["results"],
            "module_keys": run["keys"],
            # v1.9.0 (Schema 1.2.0): 模块自证证据升为一等结构
            "evidence": dict(run.get("evidence") or {}),
            "thresholds": THRESHOLDS,
            "module_presentation": {k: list(v.keys()) for k, v in MODULE_PRESENTATION.items()},
        },
    }


def _try_unjson(v):
    """若 v 是 JSON 字符串则解析为对象, 否则原样返回 (渲染前兜底, 避免裸 JSON)。"""
    if isinstance(v, str) and len(v) >= 2 and v.lstrip()[:1] in ("{", "["):
        try:
            return json.loads(v)
        except Exception:
            return v
    return v


def _fmt_value(v, indent=0, max_len=160):
    """将结果值格式化为可读文本 (紧凑风格: 列表合并、dict 内联, 避免 YAML/JSON 感)。"""
    v = _try_unjson(v)
    pad = "  " * indent
    if isinstance(v, dict):
        lines = []
        for k, val in v.items():
            label = HEADER_MAP.get(k, k)
            val = _try_unjson(val)
            if isinstance(val, (dict, list)):
                sub = _fmt_value(val, 0, max_len)
                lines.append(f"{pad}{label}: {sub}")
            else:
                lines.append(f"{pad}{label}: {val}")
        return "\n".join(lines)
    if isinstance(v, list):
        if not v:
            return f"{pad}(空)"
        if all(not isinstance(item, (dict, list)) for item in v):
            s = ", ".join("" if item is None else str(item) for item in v)
            if len(s) > max_len:
                s = s[:max_len] + "…"
            return f"{pad}{s}"
        lines = []
        for item in v:
            if isinstance(item, dict):
                inner = ", ".join(
                    f"{HEADER_MAP.get(k, k)}: {_fmt_value(x, 0, max_len)}"
                    for k, x in item.items())
                lines.append(f"{pad}- {inner}")
            else:
                lines.append(f"{pad}- {_fmt_value(item, 0, max_len)}")
        return "\n".join(lines)
    return f"{pad}{v}"


def _fmt_record_table(rt, indent=2):
    """将记录表 (headers, rows) 格式化为等宽对齐的文本表格。"""
    headers, rows = rt
    pad = "  " * indent
    cols = len(headers)
    widths = [max(len(str(h)),
                  *(len(str(r[i])) for r in rows if i < len(r)))
              for i, h in enumerate(headers)]
    widths = [min(w, 36) for w in widths]

    def _row(cells):
        return " | ".join(str(c)[:widths[i]].ljust(widths[i])
                          for i, c in enumerate(cells))
    lines = [_row(headers),
             pad + "-+-".join("-" * widths[i] for i in range(cols))]
    for r in rows:
        lines.append(_row(r))
    return "\n".join(pad + ln for ln in lines)


def render_report_text(report):
    """渲染完整的纯文本报告。"""
    if not report:
        return "（尚无诊断数据，请先运行诊断）"
    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")
    out = []
    out.append("=" * 64)
    out.append(f"  {report['app']} v{report['version']}  诊断报告")
    out.append(f"  生成时间: {g}")
    out.append("=" * 64)
    sys_i = report["system"]
    out.append("【主机信息】")
    out.append(f"  本机IP  : {sys_i.get('local_ip', '未知')}")
    out.append(f"  默认网关: {sys_i.get('gateway', '未知')}")
    out.append(f"  DNS     : {sys_i.get('dns', '未知')}")
    out.append(f"  公网IP  : {sys_i.get('public_ip', '未知')}")
    out.append("")
    # 汇总
    cnt = {}
    for st in report["summary"].values():
        cnt[st] = cnt.get(st, 0) + 1
    out.append("【诊断汇总】")
    order = ["完成", "警告", "异常", "错误", "超时", "未检测"]
    parts = [f"{k} {cnt[k]}" for k in order if cnt.get(k)]
    out.append(f"  共 {len(report['modules'])} 项: " + ", ".join(parts))
    if parts:
        ok_n = cnt.get("完成", 0)
        warn_n = cnt.get("警告", 0)
        err_n = cnt.get("异常", 0) + cnt.get("错误", 0)
        timeout_n = cnt.get("超时", 0)
        if err_n == 0 and warn_n == 0 and timeout_n == 0:
            verdict = "整体健康"
        elif err_n == 0 and timeout_n == 0:
            verdict = "整体正常，但有警告项"
        elif warn_n == 0 and timeout_n == 0:
            verdict = "存在异常项，建议排查"
        elif err_n == 0:
            verdict = "检测未全部完成，结果仅供参考"
        else:
            verdict = "存在异常与警告项，建议排查"
        tail = f"正常 {ok_n} / 警告 {warn_n} / 异常 {err_n}"
        if timeout_n:
            tail += f" / 超时 {timeout_n}"
        out.append(f"  整体状态: {verdict}（{tail}）")
    out.append("")
    # 逐模块
    out.append("【详细结果】")
    for m in report["modules"]:
        out.append("-" * 64)
        out.append(f"◆ {m['name']}  [{m['status']}]")
        # build_report 产出的模块字典用 "raw" 存原始结果 (没有 "result" 键),
        # 直接 m["result"] 会 KeyError。本函数当前无调用点, 但键名必须与实际
        # 数据结构一致, 否则哪天启用技术视图就是必崩。
        res = m.get("raw") or {}
        if "error" in res:
            out.append(f"  诊断异常: {res['error']}")
            continue
        # 优先展示 summary
        if res.get("summary"):
            out.append(f"  结论: {res['summary']}")
        if res.get("errors"):
            for e in res["errors"]:
                out.append(f"  ⚠ 问题: {e}")
        # 其余字段 (去掉已展示的)
        skip = {"summary", "errors", "timestamp", "method"}
        extra = {k: v for k, v in res.items() if k not in skip}
        if extra:
            out.append("  数据:")
            for k, v in extra.items():
                rt = _record_table(v)
                if rt is not None:
                    label = ("详细测试记录" if k in DETAIL_KEYS
                             else HEADER_MAP.get(k, k))
                    out.append(f"    ▸ {label}:")
                    out.append(_fmt_record_table(rt, 2))
                else:
                    out.append(_fmt_value({k: v}, 1))
    out.append("=" * 64)
    return "\n".join(out)


def render_report_html(report):
    """[DEPRECATED · v1.8.1] 旧版 HTML 渲染器 — export_report 已不再调用
    (主路径为 render_report_html_customer)。仅为外部脚本兼容临时保留,
    不再接受新功能/样式改动, 稳定版本后删除。"""
    import html as _html

    if not report:
        return "<p>尚无诊断数据</p>"
    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")

    def _esc(s):
        return _html.escape(str(s), quote=False)

    # 状态 → 语义键 → (前景色, 浅底色)
    SKEY = {"完成": "ok", "警告": "warn", "异常": "err", "错误": "fatal",
            "超时": "timeout", "未检测": "idle"}
    SC = {
        "ok":    ("#0e8a4f", "#e7f6ee"),
        "warn":  ("#b26a00", "#fdf3e3"),
        "err":   ("#d92d20", "#fdecec"),
        "fatal": ("#b42318", "#fbebea"),
        "timeout": ("#334155", "#e9edf3"),
        "idle":  ("#8a94a6", "#f1f3f7"),
    }

    def _sk(st):
        return SKEY.get(st, "idle")

    def _badge(status):
        fg, bg = SC[_sk(status)]
        return (f"<span class='badge' style='background:{bg};color:{fg}'>"
                f"{_esc(status)}</span>")

    def _dot(status):
        fg, _ = SC[_sk(status)]
        return f"<span class='dot' style='background:{fg}'></span>"

    def _kv_table(pairs):
        if not pairs:
            return ""
        rows = "".join(
            f"<tr><td class='k'>{_esc(HEADER_MAP.get(k, k))}</td>"
            f"<td class='v'>{_esc(v) if v is not None else '—'}</td></tr>"
            for k, v in pairs)
        return (f"<table class='tbl kv'><thead><tr>"
                f"<th>指标</th><th>值</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>")

    def _record_table_html(key, rt, is_detail=False):
        headers, rows = rt
        cap = ("详细测试记录（原始测量数据）" if is_detail
               else HEADER_MAP.get(key, key))
        head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
        body_rows = ""
        for r in rows:
            tds = "".join(f"<td>{_esc(x) if x is not None else '—'}</td>"
                          for x in r)
            body_rows += f"<tr>{tds}</tr>"
        tbl = (f"<table class='tbl'><thead><tr>{head}</tr></thead>"
               f"<tbody>{body_rows}</tbody></table>")
        if is_detail:
            return (f"<details class='detail'><summary>{_esc(cap)}"
                    f"<span class='cnt'>{len(rows)} 条</span></summary>"
                    f"{tbl}</details>")
        return f"<div class='subcap'>{_esc(cap)}</div>{tbl}"

    # ── 概览统计 ──
    cnt = {}
    for st in report["summary"].values():
        cnt[st] = cnt.get(st, 0) + 1
    order = ["完成", "警告", "异常", "错误", "超时", "未检测"]
    stats = ""
    for k in order:
        v = cnt.get(k, 0)
        fg, bg = SC[_sk(k)]
        stats += (f"<div class='stat' style='background:{bg}'>"
                  f"<div class='num' style='color:{fg}'>{v}</div>"
                  f"<div class='lab' style='color:{fg}'>{k}</div></div>")
    parts = []
    for k in order:
        if cnt.get(k):
            fg, _ = SC[_sk(k)]
            parts.append(f"<b style='color:{fg}'>{cnt[k]} {k}</b>")
    health = (f"共 {len(report['modules'])} 项检测：" + "　·　".join(parts)
              if parts else "共 0 项检测")

    # ── 主机信息 ──
    sys_i = report["system"]
    sys_cards = "".join(
        f"<div class='sys'><div class='lab'>{_esc(lab)}</div>"
        f"<div class='val'>{_esc(val)}</div></div>"
        for lab, val in [("本机 IP", sys_i.get("local_ip", "未知")),
                         ("默认网关", sys_i.get("gateway", "未知")),
                         ("DNS 服务器", sys_i.get("dns", "未知")),
                         ("公网 IP", sys_i.get("public_ip", "未知"))])

    # ── 模块卡片 ──
    blocks = []
    for m in report["modules"]:
        # 同 render_report_text: 模块原始数据在 "raw" 键下, 不是 "result"
        res = m.get("raw") or {}
        fg, bg = SC[_sk(m["status"])]
        body = ""
        if "error" in res:
            body += f"<div class='mod-err'>诊断异常：{_esc(res['error'])}</div>"
        else:
            if res.get("summary"):
                body += (f"<div class='mod-concl' style='border-left-color:{fg};"
                         f"background:{bg}'>"
                         f"<b>结论</b>　{_esc(res['summary'])}</div>")
            for e in (res.get("errors") or []):
                body += f"<div class='mod-issue'>⚠ {_esc(e)}</div>"
            skip = {"summary", "errors", "timestamp", "method"}
            extra = {k: v for k, v in res.items() if k not in skip}
            kv_pairs = []
            for k, v in extra.items():
                rt = _record_table(v)
                if rt is not None:
                    if kv_pairs:
                        body += _kv_table(kv_pairs)
                        kv_pairs = []
                    body += _record_table_html(
                        k, rt, is_detail=(k in DETAIL_KEYS))
                else:
                    kv_pairs.extend(_flatten_kv({k: v}))
            if kv_pairs:
                body += _kv_table(kv_pairs)
        blocks.append(
            f"<div class='mod' style='border-left-color:{fg}'>"
            f"<div class='mod-head'>{_dot(m['status'])}"
            f"<b class='mod-name'>{_esc(m['name'])}</b>{_badge(m['status'])}</div>"
            f"{body}</div>")

    CSS = """
:root{
  --bg:#f2f5f9; --card:#ffffff; --ink:#1b2437; --sub:#5a6472; --faint:#8a94a6;
  --line:#e3e8f0; --line-soft:#eef1f6;
  --primary:#1a56db; --primary-soft:#e8effc;
  --ok:#0e8a4f; --ok-bg:#e7f6ee;
  --warn:#b26a00; --warn-bg:#fdf3e3;
  --err:#d92d20; --err-bg:#fdecec;
  --fatal:#b42318; --fatal-bg:#fbebea;
  --idle:#8a94a6; --idle-bg:#f1f3f7;
  --radius:8px; --shadow:0 1px 2px rgba(15,28,51,.06);
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);margin:0;padding:28px 16px 64px;
  font-family:'Segoe UI','Microsoft YaHei UI','Microsoft YaHei',sans-serif;
  font-size:14px;line-height:1.65}
.wrap{max-width:1000px;margin:0 auto}

/* 页眉 */
.band{background:linear-gradient(120deg,#0f1c33 0%,#1e3a5f 55%,#24548f 100%);
  color:#fff;border-radius:10px;padding:22px 26px;display:flex;align-items:center;
  gap:14px;flex-wrap:wrap;box-shadow:0 4px 14px rgba(15,28,51,.25)}
.brand{font-size:21px;font-weight:800;letter-spacing:.3px;display:flex;align-items:center;gap:10px}
.logo{width:30px;height:30px;border-radius:7px;background:linear-gradient(135deg,#4f8ef7,#1a56db);
  display:inline-block;position:relative;flex:none}
.logo::after{content:"";position:absolute;inset:7px;border:2px solid #fff;border-radius:3px;opacity:.9}
.ver{font-size:12px;font-weight:600;color:#9db8e8;background:rgba(255,255,255,.12);
  padding:2px 8px;border-radius:999px;margin-left:4px}
.band-sub{font-size:13px;color:#c6d6f0;font-weight:500}
.band-time{margin-left:auto;font-size:12px;color:#9db8e8;
  font-family:'Cascadia Mono',Consolas,monospace}

/* 健康度总览 */
.health{margin:16px 2px 0;font-size:13.5px;color:var(--sub);line-height:1.9}
.health b{font-weight:700}

/* 统计卡 */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:14px 0 4px}
.stat{border-radius:10px;padding:14px 8px 12px;text-align:center;border:1px solid rgba(27,36,55,.05)}
.stat .num{font-size:30px;font-weight:800;line-height:1.1;
  font-family:'Cascadia Mono',Consolas,monospace}
.stat .lab{font-size:13px;font-weight:600;margin-top:2px;opacity:.85}
@media(max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}}

/* 分区标题 */
.sec{font-size:16px;font-weight:800;margin:26px 0 10px;display:flex;align-items:center;
  gap:8px;color:var(--ink)}
.sec::before{content:"";width:4px;height:16px;border-radius:2px;background:var(--primary)}

/* 主机信息 */
.sys-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.sys{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:12px 14px;box-shadow:var(--shadow)}
.sys .lab{font-size:12px;color:var(--faint);margin-bottom:3px}
.sys .val{font-size:14px;font-weight:600;color:var(--ink);word-break:break-all;
  font-family:'Cascadia Mono',Consolas,monospace}
@media(max-width:760px){.sys-grid{grid-template-columns:repeat(2,1fr)}}

/* 模块卡 */
.mod{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--primary);
  border-radius:var(--radius);padding:14px 18px;margin:12px 0;box-shadow:var(--shadow)}
.mod-head{display:flex;align-items:center;gap:9px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:none}
.mod-name{font-size:15.5px;font-weight:700;color:var(--ink)}
.badge{margin-left:auto;padding:3px 11px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.3px}

/* 结论 / 问题 */
.mod-concl{background:var(--primary-soft);border-left:3px solid var(--primary);
  border-radius:6px;padding:9px 13px;margin:10px 0 4px;font-size:13.5px;color:var(--ink)}
.mod-concl b{color:var(--primary)}
.mod-issue{background:var(--warn-bg);border-radius:6px;padding:6px 12px;margin:6px 0;
  font-size:13px;color:#7a4a00}
.mod-err{background:var(--err-bg);border-radius:6px;padding:8px 12px;margin:8px 0;
  font-size:13px;color:var(--fatal);font-weight:600}

/* 表格 */
.tbl{width:100%;border-collapse:collapse;margin:8px 0 4px;font-size:13px}
.tbl th{background:var(--primary-soft);color:#1648a8;text-align:left;font-weight:700;
  padding:6px 10px;border:1px solid #d8e3fb;white-space:nowrap}
.tbl td{padding:5px 10px;border:1px solid var(--line-soft);color:var(--ink);
  word-break:break-all;vertical-align:top}
.tbl tbody tr:nth-child(even){background:#f8fafc}
.tbl.kv td.k{width:38%;color:var(--sub);background:#f8fafc;font-weight:500}
.subcap{font-size:13px;font-weight:700;color:var(--sub);margin:10px 0 4px}

/* 可折叠明细 */
.detail{margin:10px 0 2px;border:1px dashed var(--line);border-radius:6px;background:#fbfcfe}
.detail summary{cursor:pointer;padding:8px 12px;font-size:12.5px;color:var(--faint);
  font-weight:600;user-select:none;list-style:none;display:flex;align-items:center;gap:6px}
.detail summary::-webkit-details-marker{display:none}
.detail summary::before{content:"▸";color:var(--primary);transition:transform .15s}
.detail[open] summary::before{transform:rotate(90deg)}
.detail .cnt{background:var(--idle-bg);color:var(--idle);border-radius:999px;
  font-size:11px;padding:1px 8px}
.detail .tbl{margin:0 12px 12px;width:calc(100% - 24px)}

footer{margin-top:32px;text-align:center;color:var(--faint);font-size:12px;
  border-top:1px solid var(--line);padding-top:14px}

/* 打印 */
@media print{
  body{background:#fff;padding:0;font-size:12px}
  .band{background:#1b2437 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .mod,.sys,.stat{box-shadow:none;break-inside:avoid}
  .mod-head{break-after:avoid}
  .detail[open] .tbl{display:table}
}
"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(report['app'])} 诊断报告</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<header class="band">
  <div class="brand"><span class="logo"></span>{_esc(report['app'])}
    <span class="ver">v{_esc(report['version'])}</span></div>
  <span class="band-sub">网络诊断报告</span>
  <span class="band-time">{_esc(g)}</span>
</header>
<div class="health">{health}</div>
<div class="stats">{stats}</div>
<div class="sec">主机信息</div>
<div class="sys-grid">{sys_cards}</div>
<div class="sec">详细结果</div>
{''.join(blocks)}
<footer>由 {_esc(report['app'])} v{_esc(report['version'])} 自动生成 · {_esc(g)}</footer>
</div></body></html>"""


def _flatten_kv(v, prefix=""):
    """将嵌套 dict/list 扁平化为 (key, value) 列表，便于表格展示。

    - 标量值: 直接成一行。
    - 基本值列表 (如 system_dns): 在父键下一行逗号分隔。
    - dict of primitives (如 multi_ip_macs): 内联为 "子键: 值, ..." 一行。
    - 复杂嵌套: 仍递归展开 (外层报告渲染器优先用 _record_table 渲染成多列表格)。
    """
    v = _try_unjson(v)
    rows = []

    def _is_primitive_list(x):
        return isinstance(x, list) and x and all(
            not isinstance(item, (dict, list)) for item in x)

    if isinstance(v, dict):
        for k, val in v.items():
            nk = f"{prefix}{k}"
            val = _try_unjson(val)
            if isinstance(val, dict):
                # dict 的所有值都是标量/基本值列表 -> 内联成一行
                if all(not isinstance(x, (dict,)) and
                       (not isinstance(x, list) or _is_primitive_list(x))
                       for x in val.values()):
                    subs = []
                    for sk, sv in val.items():
                        if _is_primitive_list(sv):
                            subs.append(f"{sk}: "
                                        + ", ".join(str(i) for i in sv))
                        else:
                            subs.append(f"{sk}: {sv}")
                    rows.append((nk, "； ".join(subs)))
                else:
                    rows.append((nk, ""))
                    rows.extend(_flatten_kv(val, prefix + "  "))
            elif _is_primitive_list(val):
                joined = ", ".join("" if item is None else str(item)
                                   for item in val)
                rows.append((nk, joined))
            elif isinstance(val, list) and not val:
                rows.append((nk, "(空)"))
            elif isinstance(val, list):
                rows.append((nk, ""))
                rows.extend(_flatten_kv(val, prefix + "  "))
            else:
                rows.append((nk, "" if val is None else str(val)))
    elif isinstance(v, list):
        if not v:
            rows.append((prefix + "列表", "(空)"))
        elif all(not isinstance(item, (dict, list)) for item in v):
            joined = ", ".join("" if item is None else str(item) for item in v)
            rows.append((prefix + "列表", joined))
        else:
            for i, item in enumerate(v):
                if isinstance(item, (dict, list)):
                    rows.extend(_flatten_kv(item, prefix + f"[{i+1}] "))
                else:
                    rows.append((prefix + "项",
                                 "" if item is None else str(item)))
    else:
        rows.append((prefix, "" if v is None else str(v)))
    return rows


# 报告排版约定:
#  - 形如 [ {k:v,...}, ... ] 的「同构字典列表」视为一张记录表, 应渲染为真正的多列表格,
#    而不是逐条拍平成 指标/值 两列 (那样会产生上百行难以阅读的内容)。
#  - DETAIL_KEYS 中的顶层键视为「详细测试记录」(原始测量数据), 在报告中弱化处理。
DETAIL_KEYS = {"detail", "details", "raw", "records"}

# 常用字段名 -> 中文表头 (命中则报告使用中文列名, 否则用原字段名)
HEADER_MAP = {
    "dns_server": "DNS 服务器", "dns_name": "名称", "domain": "域名",
    "resolved_ip": "解析 IP", "time_ms": "耗时(ms)", "success": "成功",
    "ok": "成功数", "total": "测试数", "avg_ms": "平均(ms)", "status": "状态",
    "address": "地址", "mac": "MAC", "interface": "接口", "metric": "跃点数",
    "gateway": "网关", "destination": "目标网络", "mask": "子网掩码",
    "routes": "路由表", "default_routes": "默认路由",
    "host_routes": "主机路由", "issues": "检测发现",
    "type": "类型", "severity": "严重级别", "message": "信息", "detail": "详情",
    "pid": "PID", "name": "名称", "count": "连接数",
    "by_state": "按状态分布",
    "system_dns": "系统 DNS", "per_server": "按服务器汇总",
    "success_count": "成功数", "total_count": "测试数",
    "avg_time_ms": "平均耗时(ms)", "assessment": "综合判定",
    "proto": "协议", "host": "主机", "port": "端口",
    "rtt_ms": "RTT(ms)", "loss": "丢包", "error": "错误",
    "targets": "探测目标", "probe_count": "探测次数", "skipped": "已跳过",
    "probe": "探针类型",
    # LAN 设备扫描
    "ip": "IP 地址", "vendor": "厂商", "is_gateway": "网关",
    "devices": "设备列表", "device_count": "设备数", "subnet": "网段",
    "local_ip": "本机 IP",
    # TCP 传输质量
    "segments_sent": "发送段", "segments_received": "接收段",
    "retransmitted": "重传段", "error_segments": "错误段",
    "conn_failures": "失败连接",
    "retrans_rate_pct": "重传率(%)", "current_connections": "当前连接",
    "connections_initiated": "发起连接", "connections_accepted": "接受连接",
    # 外网路径
    "traceroute": "路径追踪", "hop": "跳", "node": "节点",
    "target": "目标", "loss_pct": "丢包(%)", "hop_count": "跳数",
    "dns_time_ms": "DNS(ms)", "avg_rtt_ms": "平均延迟(ms)",
    "avg_loss_pct": "平均丢包(%)",
    # 外网模块字段 (区分 ping 和 TCP)
    "ping_loss_pct": "Ping 丢包(%)", "ping_avg_ms": "Ping 平均(ms)",
    "tcp_reachable": "TCP 可达", "tcp_rtt_ms": "TCP RTT(ms)",
    "tcp_port": "TCP 端口", "reachability": "可达性",
    "tcp_ok": "TCP 通", "tcp_total": "目标数",
    "unreachable_count": "不可达数", "icmp_blocked_count": "禁拼数",
    # 网络适配器
    "description": "描述", "media_type": "媒体类型",
    "is_wifi": "无线网卡", "link_speed_raw": "链路速率原始值",
    "speed_mbps": "速率(Mbps)",
    "rx_errors": "收包错误", "tx_errors": "发包错误",
    "rx_discarded": "收包丢弃", "tx_discarded": "发包丢弃",
    "nic_errors": "网卡错误统计",
    # 端口探测
    "tcp_used_port": "实际端口", "rtt_min_ms": "最小 RTT(ms)", "rtt_max_ms": "最大 RTT(ms)",
    # MTU
    "max_payload": "最大负载", "path_mtu": "路径 MTU",
    "fragmentation_risk": "分片风险", "indeterminate_pct": "不确定(%)",
    "probes": "探测次数", "mtu": "MTU",
    # 路由表（补充）
    "is_default": "是否默认",
    # IPv6
    "ipv6_global": "IPv6 全局", "ipv6_reachable": "IPv6 可达",
    # 代理检测
    "wininet": "WinINET 系统代理", "winhttp": "WinHTTP 代理",
    "env_proxies": "环境变量代理", "proxy_enable": "系统代理开关",
    "proxy_server_raw": "代理服务器(原始)", "proxy_server": "代理服务器(解析)",
    "proxy_endpoint": "代理端点", "proxy_override": "代理例外列表",
    "auto_config_url": "PAC 地址", "vpn_adapters": "VPN/虚拟网卡",
    "bypass": "绕过列表",
    "via_proxy_ok": "经代理可达", "via_proxy_status": "经代理状态码",
    "via_proxy_ms": "经代理耗时(ms)", "via_proxy_error": "经代理错误",
    "direct_ok": "直连可达", "direct_status": "直连状态码",
    "direct_ms": "直连耗时(ms)", "direct_error": "直连错误",
    "pac_reachable": "PAC 可达", "verdict": "探测结论",
    "hosts_check": "hosts 检查", "hijacked": "劫持条目",
    "suspicious": "可疑条目", "total_entries": "有效条目数",
    # NAT 类型
    "servers": "STUN 服务器", "server": "服务器",
    "mapped_addr": "映射地址", "mapped_ip": "映射 IP", "mapped_port": "映射端口",
    "nat_behavior": "映射行为", "cone_type": "锥形细分",
    "udp_blocked": "UDP 受阻", "public_ip_tcp": "HTTP 出口 IP",
    "ip_match": "出口一致性", "changed_addr": "支持变更地址",
    "local_lan_ip": "本机内网 IP",
    # 网页体检
    "url": "URL", "final_url": "最终 URL", "redirects": "重定向次数",
    "dns_ms": "DNS(ms)", "tcp_ms": "TCP 连接(ms)", "tls_ms": "TLS 握手(ms)",
    "ttfb_ms": "首字节(ms)", "total_ms": "总耗时(ms)", "status_code": "状态码",
    "tls_version": "TLS 版本", "cert_days_left": "证书剩余(天)",
    "cert_issuer": "证书颁发者", "cert_not_after": "证书到期时间",
    "fail_stage": "失败阶段", "avg_ttfb_ms": "平均首字节(ms)",
    "ok_count": "成功目标数", "redirect_chain": "重定向链",
    "fail_stages": "失败分布",
    # TCP 并发
    "levels": "分级明细", "level": "并发级别", "attempted": "发起数",
    "fail": "失败数", "success_rate": "成功率(%)",
    "p50_ms": "半数建连耗时(ms)", "p95_ms": "95%建连耗时(ms)",
    "cps": "建连速率(次/秒)", "fail_timeout": "超时失败",
    "fail_refused": "拒绝失败", "fail_other": "其他失败",
    "max_sustained": "最大可持续并发", "capped": "达到上限",
    "local_baseline": "本机回环对照", "local_baseline_level": "对照级别",
    "peak_cps": "峰值建连速率", "target_candidates": "候选目标预检",
    "established_before": "测试前连接数", "established_after": "测试后连接数",
    "bottleneck": "瓶颈位置", "max_concurrency": "阶梯上限",
    "wall_ms": "耗时(ms)",
    # 测速模块 (http / up_result / speedtest 子表)
    "http": "HTTP 下载测速", "up_result": "国内上行测速", "speedtest": "Ookla 官方测速",
    "download_mbps": "下载速率(Mbps)", "upload_mbps": "上传速率(Mbps)",
    "downloaded_bytes": "下载字节", "downloaded_mb": "下载量(MB)",
    "uploaded_bytes": "上传字节", "uploaded_mb": "上传量(MB)",
    "elapsed_s": "耗时(秒)", "threads": "连接数",
    "method": "测速方式", "sponsor": "测速节点", "server_host": "服务器地址",
    "server_latency_ms": "服务器延迟(ms)",
    "server_country": "服务器国家", "server_cc": "国家码",
    "server_id": "服务器ID", "jitter_ms": "抖动(ms)",
    "packet_loss_pct": "丢包率(%)", "result_url": "结果链接",
    "isp": "运营商", "valid": "结果有效",
    "note": "备注", "download_method": "下载方式", "upload_method": "上传方式",
    "upload_server": "上传服务器", "estimated_bandwidth": "预估宽带",
    "idle_rtt_ms": "空闲延迟(ms)", "loaded_rtt_ms": "负载延迟(ms)",
    "bufferbloat_grade": "缓冲膨胀等级", "bufferbloat_ms": "缓冲膨胀(ms)",
    "down_series": "下行采样", "up_series": "上行采样", "lat_series": "延迟采样",
    "latency_target": "延迟目标",
}


def _record_table(v):
    """若 v 是同构字典列表(记录表), 返回 (headers, rows); 否则返回 None。

    headers/rows 均为已中文化/字符串化的列表, 可直接交给 HTML 渲染。
    """
    if not isinstance(v, list) or len(v) < 1:
        return None
    if not all(isinstance(x, dict) for x in v):
        return None
    keys = []
    for x in v:
        for k in x.keys():
            if k not in keys:
                keys.append(k)
    if not keys:
        return None
    # 要求至少一半记录拥有全部字段, 才算「同构」(避免把异构字典列表误当表格)
    full = sum(1 for x in v if len(x) == len(keys))
    if full < max(1, len(v) // 2):
        return None
    headers = [HEADER_MAP.get(k, k) for k in keys]
    def _cell(v):
        # 嵌套 list/dict 用 _humanize_cell 摘要, 避免裸 JSON / Python repr
        if isinstance(v, (list, dict)):
            return _humanize_cell(v)
        if v is None:
            return "N/A"  # None 明确显示 N/A, 而不是空字符串让用户误以为缺数据
        s = str(v)
        return s if s else "N/A"
    rows = [[_cell(x.get(k)) for k in keys] for x in v]
    return headers, rows


# ============================================================
# 客户版 HTML 渲染器 (新)
# ============================================================
# 区别于老的 render_report_html:
#   - 顶部加健康评分大字
#   - "待办问题" 单独成块, 客户一眼看到要干啥
#   - 每模块只显示: 状态 + 一句话结论 + 3-5 个关键指标 + 问题/建议
#   - 技术细节默认折叠 (工程师点开看)
#   - 字段名 100% 中文化, 颜色按阈值
def _short_iface(name, max_len=32):
    """缩短网络接口名, 避免长哈希/长描述占满 metric。

    旧版 max_len=22 偏短, "VirtualBox Host-Only Network" (27字符) 等常见名
    会被截成 "VirtualBox Host-Only …" 显示不全。改 32 后:
      - "VirtualBox Host-Only Network" 完整保留
      - "ZeroTier One [1a2b3c4d5e6f7788]" (31字符) 也完整保留
      - 极长的虚拟网卡名 (如 Hyper-V 桥接) 才走截断逻辑
    """
    if not name:
        return "?"
    if len(name) <= max_len:
        return name
    if "[" in name and name.endswith("]"):
        prefix, inside = name.split("[", 1)
        inside = inside.rstrip("]")
        # 保留前缀 + 方括号里前后各 6 位 (中间用 .. 表示截断)
        if len(inside) > 12:
            keep = f"{inside[:6]}..{inside[-6:]}"
        else:
            keep = inside
        return f"{prefix.strip()} [{keep}]"
    return name[:max_len - 1] + "…"


def _html_esc(s):
    """文本节点转义: 只转义 & < > (quote=False)。

    仅用于元素内容 (如 <td>{...}</td>)。**禁止**用于 HTML 属性 —
    报告里属性普遍用单引号包裹, quote=False 不转义引号, 恶意 SSID /
    DNS 名 / hostname / URL 可闭合属性后注入标签。属性一律用 _html_attr。
    """
    import html as _html
    if s is None:
        return ""
    return _html.escape(str(s), quote=False)


def _html_attr(s):
    """HTML 属性转义: 额外转义 ' 和 " (quote=True), 属性值可安全用引号包裹。

    审计范围 (v1.5.0 P0 修复): 所有 title= / data-hint= / href= / data-mod=
    / id= / class= 的插值点都必须走这里。
    """
    import html as _html
    if s is None:
        return ""
    return _html.escape(str(s), quote=True)


def _fmt_duration(ms):
    """毫秒 → 人话耗时 (报告 Hero 用)。<=0 返回空串 (未知就不显示, 不猜)。"""
    try:
        ms = int(ms or 0)
    except (TypeError, ValueError):
        return ""
    if ms <= 0:
        return ""
    s = ms / 1000.0
    if s < 60:
        return f"{s:.1f} 秒"
    m, sec = divmod(int(round(s)), 60)
    return f"{m} 分 {sec:02d} 秒"


def _render_html_tech_block(key, raw_result, tech_keys, auto_open=True):
    """把模块的 raw 原始数据按 tech_keys 渲染成可折叠的 <details> 块。

    auto_open=True: 默认展开, 便于装维留档时数据完整可见 (用户可手动折叠)。
    """
    if not raw_result or not tech_keys:
        return ""
    out = []
    open_attr = " data-auto-open=" + chr(34) + "1" + chr(34) + " open" if auto_open else ""
    out.append(f"<details class='collapse'{open_attr}>")
    out.append(f"<summary>技术细节 <span class='cnt'>{len(tech_keys)} 项</span></summary>")
    out.append("<div class='body'>")
    for k in tech_keys:
        v = raw_result.get(k)
        if v is None:
            continue
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            # 链路速率: 自定义精简列, 避免 12 列全展示导致表格溢出
            if key == "linkspeed" and k == "adapters":
                out.append(_render_linkspeed_adapters_table(v))
                continue
            # 网页体检: 14 列全展示必溢出, 只保留用户关心的分段耗时列
            if key == "web" and k == "targets":
                out.append(_render_web_targets_table(v))
                continue
            # WiFi 信道分析: networks 嵌套列表需摘要, 避免裸 JSON
            if key == "wifi" and k == "channel_analysis":
                out.append(_render_wifi_channel_table(v))
                continue
            # 同构字典列表 → 真正的多列表格
            rt = _record_table(v)
            if rt:
                headers, rows = rt
                out.append(f"<div class='subcap'>{_html_esc(HEADER_MAP.get(k, k))} ({len(rows)} 条)</div>")
                head = "".join(f"<th>{_html_esc(h)}</th>" for h in headers)
                body = "".join(
                    "<tr>" + "".join(f"<td>{_html_esc(x or '—')}</td>" for x in r) + "</tr>"
                    for r in rows[:20]   # 折叠里最多展示 20 条, 防止 HTML 巨大
                )
                out.append(f"<div class='tbl-wrap'><table class='tbl'><thead><tr>{head}</tr></thead>"
                           f"<tbody>{body}</tbody></table></div>")
                if len(rows) > 20:
                    out.append(f"<p class='muted'>… 还有 {len(rows) - 20} 条 (如需完整数据, 导出 JSON 报告 {len(rows)} 条)</p>")
        elif isinstance(v, dict):
            # 嵌套字典 → KV 表格 (跳过纯流程字段; 布尔值中文化)
            rows = []
            for kk, vv in v.items():
                if kk in ("summary", "method", "performed", "timestamp"):
                    continue
                if vv is None or vv == "" or vv == []:
                    continue
                if isinstance(vv, bool):
                    rows.append((_html_esc(HEADER_MAP.get(kk, kk)), "是" if vv else "否"))
                elif kk == "proxy_enable" and str(vv) in ("0", "1"):
                    rows.append((_html_esc(HEADER_MAP.get(kk, kk)), "开" if int(vv) else "关"))
                elif isinstance(vv, dict):
                    rows.append((_html_esc(HEADER_MAP.get(kk, kk)),
                                 _html_esc(_pretty_dict(vv))))
                elif isinstance(vv, list):
                    # 嵌套 list 用 _humanize_cell 摘要, 避免裸 JSON
                    rows.append((_html_esc(HEADER_MAP.get(kk, kk)),
                                 _html_esc(_humanize_cell(vv))))
                else:
                    rows.append((_html_esc(HEADER_MAP.get(kk, kk)),
                                 _html_esc(_humanize_en(str(vv)))))
            if rows:
                out.append(f"<div class='subcap'>{_html_esc(HEADER_MAP.get(k, k))}</div>")
                body = "".join(
                    f"<tr><td class='k'>{k_}</td><td class='v'>{v_}</td></tr>"
                    for k_, v_ in rows)
                out.append(f"<div class='tbl-wrap'><table class='tbl kv'>"
                           f"<thead><tr><th>指标</th><th>值</th></tr></thead>"
                           f"<tbody>{body}</tbody></table></div>")
        else:
            out.append(f"<div class='subcap'>{_html_esc(HEADER_MAP.get(k, k))}</div>")
            out.append(f"<p class='mono'>{_html_esc(_humanize_en(str(v)))}</p>")
    out.append("</div></details>")
    return "".join(out)


# ============================================================
# HTML 报告图表辅助: 纯 SVG, 离线可打开, 无外部依赖
# 数据不足时返回空串, 由调用方决定隐藏对应图表卡
# ============================================================
# 状态语义键与配色 — 全报告唯一来源 (导航点 / 徽章 / 统计卡 / 图表分段共用)。
# 改颜色只改这里, 不要在各渲染函数里另立映射 (曾因三份映射并存出现过两种「警告橙」)。
STATUS_KEY = {"完成": "ok", "警告": "warn", "异常": "err", "错误": "fatal",
              "超时": "timeout", "未检测": "idle"}
STATUS_COLORS = {"ok": "#16a34a", "warn": "#d97706", "err": "#dc2626",
                 "fatal": "#7f1d1d", "timeout": "#334155", "idle": "#94a3b8"}
# 状态分布条的分段绘制顺序。「超时」是真实可达状态 (_run_module_with_timeout 返回),
# 必须绘制且参与问题判定, 否则条形留无名缺口、硬故障模块被当成灰色折叠行。
STATUS_BAR_ORDER = ["完成", "警告", "异常", "错误", "超时", "未检测"]
# 参与问题判定 (默认展开 / 问题计数) 的状态。与扣分口径已对齐:
# compute_health_score 对 异常-20 / 错误-30 / 警告-2 / 超时-10 均扣分,
# 本元组即"报告里会被标红展开"的状态, 两者一致才不会出现分数与徽章打架。
PROBLEM_STATUSES = ("警告", "异常", "错误", "超时")

# 等级配色: 阈值唯一来源是 HEALTH_GRADE_TABLE (A≥90/B≥75/C≥60/D≥40/F<40),
# 环形图与徽章按等级取色, 不再用裸分数暗阈值 (那套 ≥90/≥70 与等级表必然漂移)。
GRADE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706",
                "D": "#ea580c", "F": "#dc2626"}
GRADE_BADGE = {   # (前景色, 底色), 与环色同色系
    "A": ("#15803d", "#dcfce7"), "B": ("#4d7c0f", "#ecfccb"),
    "C": ("#b45309", "#fef3c7"), "D": ("#c2410c", "#ffedd5"),
    "F": ("#991b1b", "#fee2e2"),
}


def _html_status_color(status):
    """状态中文 -> HTML 颜色 (导航点 / 图表共用)。源自 STATUS_COLORS。"""
    return STATUS_COLORS.get(STATUS_KEY.get(status, ""), STATUS_COLORS["idle"])


def _svg_health_ring(score, grade=""):
    """健康分环形进度图 (r=54, 周长≈339.3)。配色随 HEALTH_GRADE_TABLE 等级。"""
    score = max(0, min(100, int(score or 0)))
    c = 2 * 3.14159265 * 54
    off = c * (1 - score / 100.0)
    color = GRADE_COLORS.get((grade or "").strip()[:1].upper(), GRADE_COLORS["F"])
    return (f'<svg width="132" height="132" viewBox="0 0 132 132">'
            f'<circle class="track" cx="66" cy="66" r="54"/>'
            f'<circle class="bar" cx="66" cy="66" r="54" stroke="{color}" '
            f'stroke-dasharray="{c:.2f}" stroke-dashoffset="{off:.2f}"/></svg>')


def _svg_ping_line(rtts):
    """网关逐次 ping 延迟折线图。成功样本 <3 时返回空串。

    注意: 丢包时刻无法从 ping 输出精确还原 (rtts 只含成功样本),
    故折线只画成功样本。Windows ping 对局域网 (<1ms) 一律输出
    "<1ms" → 解析为 0, 因此网关折线常整条贴 0 基线, 属正常现象。

    峰值标注 (v1.9.3): 仅当峰值 ≥50ms (图上已值得关注) 才用红点,
    否则不画点 — 网关 1ms 的峰值画红点会被误读成"故障点"。
    """
    vals = [float(x) for x in (rtts or [])
            if isinstance(x, (int, float)) and x >= 0]
    if len(vals) < 3:
        return ""
    W, H = 420, 120
    top, bot = 12, 16
    vmax = max(vals)
    ceil = max(50.0, vmax * 1.25)

    def _y(v):
        return H - bot - (v / ceil) * (H - top - bot)

    step = W / (len(vals) - 1)
    pts = " ".join(f"{i * step:.1f},{_y(v):.1f}"
                   for i, v in enumerate(vals))
    area = (f'<polygon points="{pts} {W},{H:.1f} 0,{H:.1f}" '
            f'fill="url(#np-grad)"/>')
    # 峰值 ≥50ms 才标红点 (有实际参考意义); 数值可忽略的峰值不画,
    # 避免一两个 1ms 的局域网样本在图上像"异常点"
    peak_dot = ""
    if vmax >= 50:
        max_i = vals.index(vmax)
        peak_dot = (f'<circle cx="{max_i * step:.1f}" cy="{_y(vmax):.1f}" '
                    f'r="3.5" fill="#dc2626"><title>峰值 {vmax:.0f}ms</title></circle>')
    return (f'<svg width="100%" height="120" viewBox="0 0 {W} {H}" preserveAspectRatio="none">'
            f'<defs><linearGradient id="np-grad" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="#2563eb" stop-opacity=".25"/>'
            f'<stop offset="1" stop-color="#2563eb" stop-opacity="0"/></linearGradient></defs>'
            f'<line x1="0" y1="{_y(ceil):.1f}" x2="{W}" y2="{_y(ceil):.1f}" '
            f'stroke="#e6e9f0" stroke-width="1"/>'
            f'<line x1="0" y1="{H - bot:.1f}" x2="{W}" y2="{H - bot:.1f}" '
            f'stroke="#e6e9f0" stroke-width="1"/>'
            f'{area}'
            f'<polyline points="{pts}" fill="none" stroke="#2563eb" stroke-width="2"/>'
            f'{peak_dot}'
            f'<text x="4" y="{_y(ceil) - 4:.1f}" font-size="10" fill="#94a3b8">{ceil:.0f}ms</text>'
            f'<text x="4" y="{H - 3:.1f}" font-size="10" fill="#94a3b8">0ms</text>'
            f'</svg>')


def _resolve_speed_chart_src(raw):
    """解析测速图表数据源: 优先 Ookla 官方结果 (嵌套 raw['speedtest'], 与指标卡
    _metrics_speedtest 同口径), 回退国内 HTTP 的顶层字段。

    返回 (扁平数据 dict, 来源标签)。数据缺位时对应值为 None, 由
    _svg_speed_bars 判空处理。
    """
    ookla = raw.get("speedtest")
    if isinstance(ookla, dict) and "error" not in ookla and ookla.get("download_mbps"):
        d = {k: ookla.get(k) for k in
             ("download_mbps", "upload_mbps", "server_latency_ms",
              "jitter_ms", "packet_loss_pct")}
        return d, "Ookla 官方节点"
    return ({k: raw.get(k) for k in ("download_mbps", "upload_mbps")},
            "国内节点")


def _svg_speed_bars(data):
    """测速下载/上传条形图。入参为 _resolve_speed_chart_src 的扁平 dict;
    下载/上传均无数值时返回空串。延迟/抖动/丢包仅在数据来源实际提供时
    显示真实值, 缺失显示 "—" (不伪造数字)。"""
    dl = data.get("download_mbps")
    ul = data.get("upload_mbps")
    dl = float(dl) if isinstance(dl, (int, float)) else 0.0
    ul = float(ul) if isinstance(ul, (int, float)) else 0.0
    if dl <= 0 and ul <= 0:
        return ""
    scale = max(dl, ul, 1.0) * 1.15
    bw = 258.0
    w_dl = bw * min(dl / scale, 1.0)
    w_ul = bw * min(ul / scale, 1.0)
    lat = data.get("server_latency_ms")
    lat_s = f"{lat:g}ms" if isinstance(lat, (int, float)) else "—"
    jit = data.get("jitter_ms")
    jit_s = f"{jit:g}ms" if isinstance(jit, (int, float)) else "—"
    loss = data.get("packet_loss_pct")
    loss_s = f"{loss:g}%" if isinstance(loss, (int, float)) else "—"
    return (f'<svg width="100%" height="120" viewBox="0 0 300 120" preserveAspectRatio="none">'
            f'<text x="0" y="14" font-size="10" fill="#94a3b8">下载 {format_speed(dl)}</text>'
            f'<rect x="0" y="20" width="{bw:.1f}" height="22" rx="6" fill="#dbeafe"/>'
            f'<rect x="0" y="20" width="{w_dl:.1f}" height="22" rx="6" fill="#2563eb"/>'
            f'<text x="0" y="64" font-size="10" fill="#94a3b8">上传 {format_speed(ul)}</text>'
            f'<rect x="0" y="70" width="{bw:.1f}" height="22" rx="6" fill="#fef3c7"/>'
            f'<rect x="0" y="70" width="{w_ul:.1f}" height="22" rx="6" fill="#d97706"/>'
            f'<text x="0" y="112" font-size="10" fill="#94a3b8">延迟 {lat_s} · 抖动 {jit_s} · 丢包 {loss_s}</text>'
            f'</svg>')


def _svg_status_bar(all_counts):
    """模块状态分布堆叠条 (全口径 counts)。无数据时返回空串。

    分段顺序/配色统一取自 STATUS_BAR_ORDER × _html_status_color; 除六大已知
    状态外若还冒出其他状态值, 残余部分补一段浅灰兜底, 保证条形铺满全长。
    """
    total = sum(all_counts.values())
    if total <= 0:
        return ""
    x = 0.0
    rects = []
    for st in STATUS_BAR_ORDER:
        v = all_counts.get(st, 0)
        if v <= 0:
            continue
        w = v / total * 1000
        rects.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" '
                     f'height="34" fill="{_html_status_color(st)}"/>')
        x += w
    rest = total - sum(all_counts.get(st, 0) for st in STATUS_BAR_ORDER)
    if rest > 0:
        w = rest / total * 1000
        rects.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="34" fill="#cbd5e1"/>')
        x += w
    # 段间零缝隙直角拼接, 整条用同一圆角矩形裁剪 — 每段各自 rx 会在衔接处
    # 出现圆弧缺口+缩宽细缝, 视觉上像断开的几截
    return (f'<svg width="100%" height="46" viewBox="0 0 1000 46" '
            f'preserveAspectRatio="none">'
            f'<defs><clipPath id="np-bar-clip">'
            f'<rect x="0" y="0" width="1000" height="34" rx="7"/>'
            f'</clipPath></defs>'
            f'<g clip-path="url(#np-bar-clip)">{"".join(rects)}</g></svg>')


def _build_report_nav(modules):
    """左侧浮动导航: 固定锚点 + 按 MODULE_CATEGORIES 分组的模块树。

    只列出本次实际运行的模块 — 子集运行 (--module speedtest …) 时未执行的
    模块在页面上没有对应锚点 id, 渲染成死链会让界面显得损坏。
    """
    by_key = {m["key"]: m for m in modules}
    fixed = [
        ("报告概览", "#overview", "#2563eb"),
        ("待办问题", "#todo", "#dc2626"),
        ("状态统计", "#stats", "#f59e0b"),
        ("关键指标图", "#charts", "#0284c7"),
        ("检测结果一览", "#list", "#64748b"),
    ]
    out = ['<div class="g">导航</div>']
    for name, href, color in fixed:
        out.append(f'<a href="{href}"><span class="st" '
                   f'style="background:{color}"></span>{name}</a>')
    for cat, keys, _desc in MODULE_CATEGORIES:
        present = [k for k in keys if k in by_key]
        if not present:
            continue   # 整个分类都没跑就不渲染该分组
        out.append(f'<div class="grp">{_html_esc(cat)}</div>')
        out.append('<div class="mods">')
        for key in present:
            m = by_key[key]
            color = _html_status_color(m["status"])
            out.append(f'<a href="#mod-{_html_attr(key)}">'
                       f'<span class="st" style="background:{color}"></span>'
                       f'{_html_esc(m["name"])}</a>')
        out.append('</div>')
    return "".join(out)


# 常见英文工具原句 → 中文 (代理检测的 netsh/注册表输出等)
_EN_ZH_MAP = {
    "direct access (no proxy server).": "直连 (未配置代理)",
    "direct access (no proxy server)": "直连 (未配置代理)",
    "proxy is set": "已配置代理服务器",
}


def _humanize_en(s):
    """把常见英文工具原句翻成中文, 其余原样返回 (只做展示层美化)。"""
    if not isinstance(s, str):
        return s
    return _EN_ZH_MAP.get(s.strip().lower(), s)


def _pretty_dict(d, max_len=160):
    """把 dict 值内联成人话: "http: 1.2.3.4:8080, https: ...", 避免裸 JSON。"""
    try:
        parts = []
        for k, v in d.items():
            if isinstance(v, (dict, list)):
                v = _humanize_cell(v)
            parts.append(f"{k}: {v}")
        s = ", ".join(parts)
        return s if len(s) <= max_len else s[:max_len - 1] + "…"
    except Exception:
        return json.dumps(d, ensure_ascii=False)[:max_len]


def _humanize_cell(v, max_len=120):
    """把表格单元格中的嵌套 list/dict 值摘要成人话, 避免裸 JSON / Python repr。

    - list of dict (如 WiFi channel_analysis.networks): "3 个: SSID1(-65dBm), SSID2(-72dBm)"
    - list of scalar: "a, b, c"
    - dict: "k1: v1, k2: v2" (调用 _pretty_dict)
    - 空 list/dict: "—"
    - 其他: str(v)

    max_len: 摘要最大长度, 超出截断 (表格单元格不宜过长)。
    """
    if v is None:
        return "—"
    if isinstance(v, list):
        if not v:
            return "—"
        # list of dict: 提取每个 dict 的核心字段做摘要
        if all(isinstance(x, dict) for x in v):
            # WiFi networks 列表: 优先用 ssid + signal
            if all("ssid" in x or "bssid" in x for x in v):
                bits = []
                for x in v[:8]:
                    ssid = x.get("ssid") or x.get("bssid") or "?"
                    sig = x.get("signal")
                    bits.append(f"{ssid}({sig}dBm)" if sig is not None else str(ssid))
                head = ", ".join(bits)
                suffix = f" 等 {len(v)} 个" if len(v) > 8 else f" ({len(v)} 个)"
                s = head + suffix
            else:
                # 通用 list of dict: 每个取前 2 个字段
                bits = []
                for x in v[:5]:
                    items = list(x.items())[:2]
                    bits.append(", ".join(f"{k}: {val}" for k, val in items))
                s = "; ".join(bits)
                if len(v) > 5:
                    s += f" 等 {len(v)} 项"
            return s if len(s) <= max_len else s[:max_len - 1] + "…"
        # list of scalar
        s = ", ".join("" if x is None else str(x) for x in v)
        return s if len(s) <= max_len else s[:max_len - 1] + "…"
    if isinstance(v, dict):
        if not v:
            return "—"
        return _pretty_dict(v, max_len=max_len)
    s = str(v)
    return s if s else "—"


def _render_web_targets_table(targets):
    """网页体检专用: 只展示 8 个关键列, 避免 14 列全展示导致表格溢出。

    砍掉的列 (TLS 版本/证书剩余/颁发者/到期时间/解析 IP/重定向次数/最终 URL)
    属证书与重定向细节, 完整数据在 JSON 报告; 表格宽了必溢出。
    """
    column_map = [
        ("url", "URL"), ("status_code", "状态码"),
        ("dns_ms", "DNS(ms)"), ("tcp_ms", "TCP 连接(ms)"),
        ("tls_ms", "TLS 握手(ms)"), ("ttfb_ms", "首字节(ms)"),
        ("total_ms", "总耗时(ms)"), ("fail_stage", "失败阶段"),
    ]
    head = "".join(f"<th>{_html_esc(l)}</th>" for _, l in column_map)
    body_rows = []
    for t in targets[:20]:
        cells = []
        for key, _ in column_map:
            v = t.get(key)
            cells.append("—" if v is None else _html_esc(str(v)))
        body_rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    body = "".join(body_rows)
    more = (f"<p class='muted'>… 还有 {len(targets) - 20} 条 (如需完整数据, "
            f"导出 JSON 报告 {len(targets)} 条)</p>" if len(targets) > 20 else "")
    return (f"<div class='subcap'>探测目标 ({len(targets)} 条, 仅展示关键列; "
            f"证书/重定向等完整字段见 JSON 报告)</div>"
            f"<div class='tbl-wrap'><table class='tbl'><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table></div>{more}")


def _render_linkspeed_adapters_table(adapters):
    """链路速率专用: 只展示真正有用的 5 列。

    原 _record_table 把 adapters dict 的全部 12 个 key 都展开, 导致:
      - 重复列 (链路速率原始值 / 速率 Mbps / 综合判定 含相同信息)
      - 冗余列 (4 个收发包错误列几乎都是 0/N/A)
      - 难懂列 (无线网卡 True/False、媒体类型 802.3/Native 802.11)
      - 长名 (ZeroTier One [1a2b3c4d5e6f7788] + Realtek 8822CE ...) 把表格撑爆
    客户关心的是: 名字 + 描述 + 状态 + 是否WiFi + 速率(Mbps) + 档位判定。其他进 JSON。
    """
    # 选定的展示列 + 中文化表头
    column_map = [
        ("name", "名称"),
        ("description", "描述"),
        ("status", "状态"),
        ("speed_mbps", "速率 (Mbps)"),
        ("assessment", "档位判定"),
    ]
    head = "".join(f"<th>{_html_esc(label)}</th>" for _, label in column_map)
    body_rows = []
    for a in adapters[:20]:  # 折叠里最多 20 条
        cells = []
        for key, _ in column_map:
            v = a.get(key)
            if v is None:
                cells.append("—")
            elif key == "speed_mbps":
                cells.append(_html_esc(str(v)))
            elif key == "name":
                cells.append(_html_esc(_short_iface(str(v), 36)))
            else:
                cells.append(_html_esc(str(v)))
        body_rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    body = "".join(body_rows)
    return (f"<div class='subcap'>adapters ({len(adapters)} 条, 仅展示关键列; "
            f"完整 12 列字段见 JSON 报告)</div>"
            f"<div class='tbl-wrap'><table class='tbl'><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table></div>")


def _render_wifi_channel_table(channel_analysis):
    """WiFi 信道分析专用: 只展示用户关心的 6 列, networks 嵌套列表转摘要。

    原 _record_table 把 networks 列直接 str(list) 显示成 Python repr,
    一列塞几十个网络的完整 dict, 行高爆炸且用户看不懂。现改为:
      - 只展示: 信道 / 频段 / 网络数 / 干扰分 / 干扰等级 / 网络摘要
      - networks 列用 _humanize_cell 摘要为 "3 个: SSID1(-65dBm), SSID2(-72dBm)"
    """
    column_map = [
        ("channel", "信道"),
        ("band", "频段"),
        ("network_count", "网络数"),
        ("interference_score", "干扰分"),
        ("interference_level", "干扰等级"),
        ("networks", "网络列表"),
    ]
    head = "".join(f"<th>{_html_esc(label)}</th>" for _, label in column_map)
    body_rows = []
    for ca in channel_analysis[:20]:
        cells = []
        for key, _ in column_map:
            v = ca.get(key)
            if key == "networks":
                # 嵌套 list of dict → 摘要
                cells.append(_html_esc(_humanize_cell(v)))
            elif v is None:
                cells.append("—")
            else:
                cells.append(_html_esc(str(v)))
        body_rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    body = "".join(body_rows)
    more = (f"<p class='muted'>… 还有 {len(channel_analysis) - 20} 条 (如需完整数据, "
            f"导出 JSON 报告 {len(channel_analysis)} 条)</p>"
            if len(channel_analysis) > 20 else "")
    return (f"<div class='subcap'>信道分析 ({len(channel_analysis)} 条, "
            f"网络列表为摘要; 完整 BSSID/信号/认证等见 JSON 报告)</div>"
            f"<div class='tbl-wrap'><table class='tbl'><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table></div>{more}")


def render_report_html_customer(report):
    """渲染客户版 HTML 报告。

    输入: build_report() 的输出 (双视图)
    输出: 完整可独立打开的 HTML 字符串
    """
    if not report:
        return "<p>尚无诊断数据，请先运行诊断</p>"

    import html as _html
    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")
    sys_i = report["system"]
    health = report["health"]
    counts = report["counts"]
    modules = report["modules"]
    by_key = {m["key"]: m for m in modules}   # 一次建索引, 下文各处复用

    # 状态语义键: 引用全局唯一来源 (见 STATUS_COLORS 定义处), 不要在本函数
    # 里再立局部映射 — 多份映射并存曾导致同一份报告出现两种「警告橙」。
    SKEY = STATUS_KEY

    # ── 顶部 hero (方案 A: 白卡 + SVG 环形健康分) ──
    nav_html = _build_report_nav(modules)

    # meta chips: 本机 / 网关 / 公网 / DNS / 出口位置 / IPv6
    hero_meta = []
    hero_meta.append(f"本机 <b>{_html_esc(sys_i.get('local_ip') or '?')}</b>")
    if sys_i.get("gateway"):
        hero_meta.append(f"网关 <b>{_html_esc(sys_i['gateway'])}</b>")
    if sys_i.get("public_ip"):
        hero_meta.append(f"公网 <b>{_html_esc(sys_i['public_ip'])}</b>")
    if sys_i.get("dns"):
        hero_meta.append(f"DNS <b>{_html_esc(sys_i['dns'])}</b>")
    if sys_i.get("asn") or sys_i.get("geo"):
        hero_meta.append(f"📍 <b>{_html_esc(' / '.join(x for x in (sys_i.get('geo'), sys_i.get('asn')) if x))}</b>")
    if sys_i.get("ipv6_public_ip"):
        hero_meta.append(f"IPv6 <b>{_html_esc(sys_i['ipv6_public_ip'])}</b>")
    # v1.5.0: 检测耗时 + 检测范围。只跑几个模块时健康分 100 极容易被读成
    # "23 项全正常", 必须显式写出覆盖了多少项
    dur_txt = _fmt_duration(report.get("duration_ms"))
    if dur_txt:
        hero_meta.append(f"耗时 <b>{_html_esc(dur_txt)}</b>")
    sel = report.get("selected_modules")
    tot = report.get("total_modules")
    if isinstance(sel, int) and isinstance(tot, int) and tot > 0:
        if sel < tot:
            # 部分检测: title 里说清未覆盖多少项, 避免只看到分数就下结论
            hero_meta.append(
                (f"检测范围 <b>{sel}/{tot}</b> 项",
                 f"本次仅运行所选模块, 其余 {tot - sel} 项未检测"))
        else:
            hero_meta.append(f"检测范围 <b>{tot} 项全覆盖</b>")
    # chip 支持 (内容, title) 二元组, 避免在 .hero .meta span 里再套一层 span
    meta_chips = "".join(
        (f"<span title='{_html_attr(m[1])}'>{m[0]}</span>"
         if isinstance(m, tuple) else f"<span>{m}</span>")
        for m in hero_meta)

    score = health.get("score", 0)
    grade_key = str(health.get("grade") or "").strip()[:1].upper()
    lbl_fg, lbl_bg = GRADE_BADGE.get(grade_key, GRADE_BADGE["C"])
    score_ring = _svg_health_ring(score, grade_key)

    # 阶段 C · v1.3.0: 根因摘要 (hero 之后紧接, 客户第一屏直接看到主要问题)
    # v1.5.0: 传入完整 report, 用于生成"一句话报障"
    diagnosis_section = _render_diagnosis_section_html(
        report.get("diagnosis", {}), report=report)

    hero = f"""
<header class="hero" id="overview">
  <div style="flex:1;min-width:0">
    <div class="app"><div class="mark"></div>
      <b>{_html_esc(report['app'])}</b><span class="ver">v{_html_esc(report['version'])}</span></div>
    <h1>网络诊断报告</h1>
    <div class="sub">{_html_esc(health.get('verdict', ''))} · 生成于 {_html_esc(g)}</div>
    <div class="meta">{meta_chips}</div>
  </div>
  <div class="gauge">
    {score_ring}
    <div class="in"><div class="num">{score}</div><div class="lbl" style="color:{lbl_fg};background:{lbl_bg}">{_html_esc(health.get('label', ''))}</div></div>
  </div>
</header>"""

    # ── 信息条 (模块总数 / 豁免 / 扣分项 / 生成时间) ──
    # 「扣分项」必须用 counts (report["counts"], 不含豁免模块的扣分口径),
    # 与 compute_health_score 一致; 用全口径会在 100 分绿环旁边谎报扣分。
    # all_counts (全口径) 从 report["summary"] 派生即可, 供状态分布条使用。
    all_counts = Counter(report.get("summary", {}).values())
    total_modules = len(modules)
    exempt_count = report.get("exempt_count", 0) or 0
    err_cnt = counts.get("异常", 0) + counts.get("错误", 0)
    warn_cnt = counts.get("警告", 0)
    timeout_cnt = counts.get("超时", 0)
    band_bits = [f"共 <b>{total_modules}</b> 个模块"]
    if exempt_count:
        band_bits.append(f"评分豁免 <b>{exempt_count}</b>（iperf3 / ipv6 / proxy / nattype）")
    deduct_bits = []
    if err_cnt:
        deduct_bits.append(f"<b>{err_cnt}</b> 异常级")
    if warn_cnt:
        deduct_bits.append(f"<b>{warn_cnt}</b> 警告级")
    if timeout_cnt:
        deduct_bits.append(f"<b>{timeout_cnt}</b> 超时")
    if deduct_bits:
        band_bits.append("扣分项 " + " / ".join(deduct_bits))
    band_html = ('<div class="band">' +
                 '<span class="sep"></span>'.join(band_bits) + '</div>')

    # ── 待办问题 ──
    # 1) 收集所有 issue; 2) 按 (severity, text) 去重避免多模块重复同一警告;
    # 3) 顶部列表只展示异常/错误/警告, 信息级不进顶部 (详情里仍可见)
    todo_issues = []
    seen_keys = {}
    for m in modules:
        for issue in m.get("issues", []) or []:
            text = (issue.get("text", "") or "").strip()
            dedup_key = (issue.get("severity", "信息"), text)
            hit = seen_keys.get(dedup_key)
            if hit is not None:
                # 同样文案合并成一条卡, 但记下波及的模块数 —
                # 否则 23 个模块同样超时会压成 1 条, 与"23 个问题模块已展开"自相矛盾
                hit["_dup"] += 1
                if m["name"] not in hit["_modules"]:
                    hit["_modules"].append(m["name"])
                continue
            entry = {**issue, "_module": m["name"], "_status": m["status"],
                     "_dup": 1, "_modules": [m["name"]]}
            seen_keys[dedup_key] = entry
            todo_issues.append(entry)

    sev_order = {"异常": 0, "错误": 0, "警告": 1, "信息": 2}
    todo_issues.sort(key=lambda i: sev_order.get(i.get("severity", "信息"), 3))

    # 顶部只展示需关注条目 (异常/错误/警告), 信息级不进顶部列表; 最多展示 10 条, 溢出时给出提示
    need_attention = [i for i in todo_issues if i.get("severity", "信息") in ("异常", "错误", "警告")]
    top_issues = need_attention[:10]

    if top_issues:
        # 合并"同来源 + 同影响 + 同建议"的条目为一张卡 (如 IPv6 的两条异常):
        # 标题用「；」连接多条问题, 卡片数更少、建议不重复刷屏
        merged = []
        merge_index = {}
        for issue in top_issues:
            gkey = (issue.get("_module", ""), issue.get("impact", ""),
                    issue.get("action", ""), issue.get("severity", "信息"))
            if gkey in merge_index:
                hit = merged[merge_index[gkey]]
                hit["_texts"].append(issue.get("text", ""))
                # 合并卡片时累加波及模块数, 否则"影响 23 个模块"会被算成 1
                hit["_dup"] = hit.get("_dup", 1) + issue.get("_dup", 1)
                for nm in issue.get("_modules", []):
                    if nm not in hit["_modules"]:
                        hit["_modules"].append(nm)
            else:
                merge_index[gkey] = len(merged)
                merged.append({**issue, "_texts": [issue.get("text", "")]})
        todo_blocks = []
        for issue in merged:
            sev = issue.get("severity", "信息")
            sev_class = "err" if sev in ("异常", "错误") else "warn"
            impact = issue.get("impact", "")
            action = issue.get("action", "")
            text = "；".join(t for t in issue["_texts"] if t)
            module = issue.get("_module", "")
            raw_summary = issue.get("raw_summary", "")
            # 把 raw_summary 也加到来源 meta 行, 让装维一眼看到原始数据
            # (例如网关丢包: 立即看到 "20 发 / 19 收 / 1 丢", 不必展开技术细节)
            meta_line = f"📍 来源: {_html_esc(module)}"
            dup = issue.get("_dup", 1) or 1
            if dup > 1:
                # 去重后必须告诉用户波及范围, 否则顶部"1 项需要您关注"与
                # 下方"23 个问题模块已展开"看起来互相打架
                mods = issue.get("_modules", []) or []
                scope = "、".join(mods[:4]) + (" 等" if len(mods) > 4 else "")
                meta_line += (f" · ⚠ 波及 <b>{dup}</b> 个模块"
                              f"（{_html_esc(scope)}）")
            if raw_summary:
                meta_line += f" · 📊 {_html_esc(raw_summary)}"
            todo_blocks.append(f"""
<div class="issue {sev_class}">
  <h3><span class="sev">{_html_esc(sev)}</span>{_html_esc(text)}</h3>
  <div class="meta">{meta_line}</div>
  {f"<div class='impact'>📌 影响: {_html_esc(impact)}</div>" if impact else ""}
  {f"<div class='action'>💡 建议: {_html_esc(action)}</div>" if action else ""}
</div>""")
        extra_bits = []
        # 会诊引导: 存在异常级问题时提示升级路径 (现场解决不了 → 带报告回去)
        critical_cnt = sum(1 for i in need_attention
                           if i.get("severity") in ("异常", "错误"))
        if critical_cnt:
            todo_blocks.append(f"""
<div class="issue consult">
  <h3><span class="sev">会诊</span>{critical_cnt} 项异常级问题的现场处置指引</h3>
  <div class="impact">📌 影响: 异常级问题按上述建议现场处理后仍存在的, 多涉及线路质量、运营商侧或设备本身缺陷, 现场手段有限</div>
  <div class="action">💡 建议: 保留本 HTML 报告与同名 <b>.json</b> 文件带回交专家会诊 — .json 内含完整原始测量数据 (逐跳路径、时序曲线、原始统计), 供后台深入分析; 客户处可先留存 HTML 版说明</div>
</div>""")
        hidden_cnt = len(need_attention) - len(top_issues)
        if hidden_cnt > 0:
            extra_bits.append(f"顶部仅展示前 10 条, 另有 {hidden_cnt} 条见下方模块详情")
        info_cnt = sum(1 for i in todo_issues if i.get("severity", "信息") == "信息")
        if info_cnt > 0:
            extra_bits.append(f"另有 {info_cnt} 条信息项可查看下方模块详情")
        info_extra = (f" <span class='extra-count'>({'；'.join(extra_bits)})</span>"
                      if extra_bits else "")
        todo_section = f"""
<div class="sec" id="todo"><h2><span class="icon">⚠</span>{len(need_attention)} 项需要您关注{info_extra}</h2></div>
<div class="todo">{"".join(todo_blocks)}</div>"""
    elif todo_issues:
        todo_section = """
<div class="sec" id="todo"><h2><span class="icon">✓</span>所有核心检测通过</h2></div>
<div class="todo ok">
  <div class="todo-head">✓ 网络状态良好</div>
  <div class="impact">所有核心检测均正常, 部分提示项可在下方模块详情查看。</div>
</div>"""
    else:
        todo_section = f"""
<div class="sec" id="todo"><h2><span class="icon">✓</span>所有检测通过</h2></div>
<div class="todo ok">
  <div class="todo-head">✓ 网络状态良好</div>
  <div class="impact">全部 {len(modules)} 项检测均正常, 无需特别处理。</div>
</div>"""

    # ── 统计卡片 ──
    # 始终显示全部 6 个卡片 (含 0 值), 与 stats-grid 的 6 列布局对齐
    stats_order = ["完成", "警告", "异常", "错误", "超时", "未检测"]
    stat_items = [(k, counts.get(k, 0)) for k in stats_order]
    stat_cards = "".join(
        f"<div class='stat-card {SKEY.get(k, 'idle').replace('fatal', 'err')}'>"
        f"<div class='count'>{v}</div>"
        f"<div class='label'>{k}</div></div>"
        for k, v in stat_items
    )
    # 模块总数 + 豁免模块数 (已在 hero 段计算 total_modules / exempt_count,
    # 避免 stats-grid 只显示部分模块误导用户以为模块变少了)。
    # 注意两种口径并存, 必须在文案里讲清楚, 否则并排的统计卡(扣分口径)与
    # 状态分布条(全口径)数字不一致会让人以为算错了:
    #   counts  = 扣分口径, 排除豁免模块  → 统计卡
    #   summary = 全口径,   含豁免模块    → 状态分布条 / 检测结果一览
    stats_caption = ""
    if total_modules:
        scored_total = sum(v for _, v in stat_items)
        if exempt_count:
            stats_caption = (
                f"<div class='stats-caption'>上方为<b>扣分口径</b> {scored_total} 个模块"
                f"（全量 {total_modules} 个, 其中 {exempt_count} 个评分豁免不计入: "
                f"iperf3 / ipv6 / proxy / nattype）；下方状态分布条为<b>全口径</b> "
                f"{total_modules} 个模块</div>")
        else:
            stats_caption = f"<div class='stats-caption'>共 {total_modules} 个模块</div>"
    stats_section = f"""
<div class="sec" id="stats"><h2><span class="icon">📊</span>状态统计</h2></div>
<div class="stats-grid">{stat_cards}</div>{stats_caption}"""

    # ── 检测结果一览 ──
    overview_items = []
    for m in modules:
        st = m["status"]
        sk = SKEY.get(st, "idle")
        # 概览行只显示"结论"前 60 字, 避免太长
        verdict_short = m["verdict"][:60] + ("…" if len(m["verdict"]) > 60 else "")
        overview_items.append(
            f"<li>"
            f"<a href='#mod-{_html_attr(m['key'])}' title='跳转到 {_html_attr(m['name'])} 详细结果'>"
            f"<span class='dot {sk}'></span>"
            f"<span class='name'>{_html_esc(m['name'])}</span>"
            f"<span class='verdict'>{_html_esc(verdict_short)}</span>"
            f"<span class='badge {sk}'>{_html_esc(st)}</span>"
            f"</a>"
            f"</li>"
        )
    overview_section = f"""
<div class="sec" id="list"><h2><span class="icon">📋</span>检测结果一览</h2></div>
<div class="overview"><ul>{"".join(overview_items)}</ul></div>"""

    # ── 图表区 (纯 SVG, 数据不足时对应图卡自动隐藏) ──
    chart_cards = []

    gw_mod = by_key.get("gateway") or {}
    gateway_raw = gw_mod.get("raw") or {}
    ping_info = (gateway_raw or {}).get("ping") or {}
    ping_rtts = ping_info.get("rtts") or []
    ping_chart = _svg_ping_line(ping_rtts)
    if ping_chart:
        cap_bits = [f"共 {len(ping_rtts)} 次成功样本"]
        if isinstance(ping_info.get("avg_ms"), (int, float)):
            avg = ping_info["avg_ms"]
            # Windows ping 对局域网 (<1ms) 输出整数粒度 0, 直写"平均 0ms"
            # 会被误读成"数据有问题" — 有样本时按 <1ms 表达 (v1.9.3)
            cap_bits.append("平均 <1ms" if (avg < 1 and ping_rtts)
                            else f"平均 {avg:g}ms")
        peak = max(ping_rtts) if ping_rtts else 0
        if isinstance(peak, (int, float)) and peak > 0:
            cap_bits.append(f"峰值 {peak:g}ms")
        if isinstance(ping_info.get("loss_pct"), (int, float)) \
                and ping_info.get("loss_pct", 0) > 0:
            cap_bits.append(f"丢包 {ping_info['loss_pct']}%")
        chart_cards.append(
            f"<div class='chart'><h4>网关延迟时间序列 <span class='tag'>逐次 Ping</span></h4>"
            f"{ping_chart}<div class='cap'>" + " · ".join(cap_bits) + "。</div></div>")

    sp_mod = by_key.get("speedtest") or {}
    speed_src, speed_method = _resolve_speed_chart_src(sp_mod.get("raw") or {})
    speed_chart = _svg_speed_bars(speed_src)
    if speed_chart:
        cap_bits = []
        for kk, lab in (("download_mbps", "下载"), ("upload_mbps", "上传")):
            v = speed_src.get(kk)
            if isinstance(v, (int, float)) and v > 0:
                cap_bits.append(f"{lab} {format_speed(v)}")
        chart_cards.append(
            f"<div class='chart'><h4>宽带测速 <span class='tag'>{_html_esc(speed_method)}</span></h4>"
            f"{speed_chart}<div class='cap'>" + " · ".join(cap_bits) + "。</div></div>")

    status_chart = _svg_status_bar(all_counts)
    if status_chart:
        dist = " · ".join(f"{k} {v}" for k, v in all_counts.items())
        chart_cards.append(
            f"<div class='chart wide'><h4>状态分布 <span class='tag'>{total_modules} 模块</span></h4>"
            f"{status_chart}<div class='cap'>" + dist
            + ("（含评分豁免模块）" if exempt_count else "") + "</div></div>")

    if chart_cards:
        charts_section = (f'<div class="sec" id="charts"><h2><span class="icon">📈</span>关键指标图</h2></div>'
                          f'<div class="charts">{"".join(chart_cards)}</div>')
    else:
        charts_section = ""

    # ── 详细模块 ──
    # v1.5.0: 模块卡默认只展开首要根因涉及的模块。23 个模块里若有 5 个异常,
    # 旧逻辑会一次刷出 5 张巨型卡片把客户第一屏淹没 — 只留主角展开
    root_causes = (report.get("diagnosis") or {}).get("root_causes") or []
    primary_modules = set(root_causes[0].get("affected_modules") or []) \
        if root_causes else set()

    mod_blocks = []
    for m in modules:
        st = m["status"]
        sk = SKEY.get(st, "idle")
        # 关键指标
        metrics = m.get("key_metrics", [])
        if metrics:
            metric_html = []
            for me in metrics:
                # 空值指标 (—/N/A/无) 没有信息量, 不占卡片格
                if str(me.get("value", "")).strip() in ("—", "N/A", "无", ""):
                    continue
                level = me.get("level", "ok")
                hint = me.get("hint", "")
                # 指标卡保持清爽: 数字为主, 名称在下, 任何说明文字都不进卡面
                # (包括 warn/err 也不再 inline 显示), 全部进悬停提示 —
                # 卡面只靠颜色传达"这条需要关注", 点数超过 5 个时长说明挤
                # 变形, 移到 title 是更可读的方案
                # title 包含完整名/值/说明, 窄屏 ellipsis 截断后仍能看到
                full_title = f"{me.get('label','')}: {me.get('value','')}"
                if hint:
                    full_title += f"\n💡 {hint}"
                # 数值在上、名称在下 (flex-column), 长名称可换行不再截断
                # data-hint 供触摸设备点击展开 (桌面 hover 走 title)
                metric_html.append(
                    f"<div class='metric' title='{_html_attr(full_title)}'"
                    f"{' data-hint=\'' + _html_attr(hint) + '\'' if hint else ''}>"
                    f"<span class='v {level}'>{_html_esc(me['value'])}</span>"
                    f"<span class='lab'>{_html_esc(me['label'])}</span>"
                    f"</div>"
                )
            metrics_html = f"<div class='metrics'>{''.join(metric_html)}</div>"
        else:
            metrics_html = ""

        # 问题: 按 (severity, text) 去重 — 与顶部"需关注/信息项"计数口径一致
        # (顶部按 (severity, text) 去重), 保证"计数 = 卡片实际渲染行数"。
        # 注意: 不再按 action 去重 — 多条不同问题共享同一建议时 (如 IPv6/
        # 多出口模块的同 action 信息项), 每条都必须可见, 否则顶部计数
        # 与卡片内容对不上。
        issues = m.get("issues", []) or []
        if issues:
            # 先按 (severity, text) 去重 (与顶部计数口径一致), 再把
            # "同一条建议"的多条问题合并到一组: 问题列表只出现一次建议,
            # 避免同一模块里 💡 建议重复刷屏 (如 IPv6 的两条异常共享同一建议)
            deduped = []
            seen_issue_keys = set()
            for issue in issues:
                sev = issue.get("severity", "信息")
                text = (issue.get("text", "") or "").strip()
                action = (issue.get("action", "") or "").strip()
                act_key = (sev, text)
                if not text or act_key in seen_issue_keys:
                    continue
                seen_issue_keys.add(act_key)
                deduped.append((sev, text, action))
            # 按建议分组 (保持出现顺序): {action: [(sev, text), ...]}
            groups = []
            group_index = {}
            for sev, text, action in deduped:
                if action and action in group_index:
                    groups[group_index[action]][1].append((sev, text))
                else:
                    group_index[action] = len(groups)
                    groups.append((action, [(sev, text)]))
            issue_html = []
            for action, items in groups:
                for sev, text in items:
                    sev_class = ("err" if sev in ("异常", "错误")
                                 else "warn" if sev == "警告" else "")
                    info_cls = sev_class if sev_class else "info"
                    issue_html.append(
                        f"<div class='impact-line {info_cls}'>"
                        f"<b>[{_html_esc(sev)}]</b> {_html_esc(text)}"
                        f"</div>"
                    )
                # 纯信息级的条目不带建议 (如 "假网关属设计行为" 却跟一条
                # "联系网络管理员" 的建议, 自相矛盾且徒增噪音)
                if action and any(s in ("异常", "错误", "警告") for s, _ in items):
                    issue_html.append(
                        f"<div class='action-line'>💡 {_html_esc(action)}</div>"
                    )
            issues_html = "".join(issue_html)
        else:
            issues_html = ""

        # 折叠策略 (v1.5.0 收窄):
        #   有根因 → 只自动展开"首要根因"涉及的模块, 其余问题模块折叠
        #   无根因 → 退回旧行为, 所有问题模块展开 (规则没命中时不能把异常藏起来)
        # 「超时」也是硬故障 (测了但没结果), 两种情况都不该被当成无关紧要的灰行
        problem_status = st in PROBLEM_STATUSES
        auto_open = (m["key"] in primary_modules) if primary_modules else problem_status
        tech_html = ""
        if m.get("has_tech_details"):
            pres = MODULE_PRESENTATION.get(m["key"], {})
            tech_keys = pres.get("tech_keys", [])
            tech_html = _render_html_tech_block(
                m["key"], m.get("raw", {}), tech_keys,
                auto_open=auto_open)

        # WiFi 等模块原始数据全空时, 给出友好提示而非空列表
        empty_note_html = ""
        if m["key"] == "wifi":
            raw = m.get("raw", {}) or {}
            nets = raw.get("networks") or []
            chans = raw.get("channel_analysis") or []
            if not nets and not chans:
                empty_note_html = "<div class='impact-line warn'><b>[提示]</b> 当前未连接 Wi-Fi, 因此未扫描周边网络与信道占用 (这是正常现象, 而非故障)。</div>"

        # 整个模块卡 (方案 A: details 折叠, 问题模块自动展开)
        verdict = m.get("verdict", "")
        # 摘要行 (折叠态) 空间受限: 截断 60 字 (与「检测结果一览」同口径),
        # 全文走 title 悬停。v1.5.3: 只截摘要行 — 卡片正文「结论」行没有空间
        # 约束, 打印/PDF 不显示 title, 截断会让纸质留档永久缺文
        v_short = verdict[:60] + ("…" if len(verdict) > 60 else "")
        v_title = f' title="{_html_attr(verdict)}"' if len(verdict) > 60 else ""
        explain = MODULE_EXPLAINS.get(m["key"], "")
        explain_html = (f"<div class='explain'>📖 {_html_esc(explain)}</div>"
                        if explain else "")
        # 模块图标
        mod_icons = {
            "ok": "✓",
            "warn": "⚠",
            "err": "✕",
            "fatal": "✕",
            "timeout": "⏱",
            "idle": "○"
        }
        mod_icon = mod_icons.get(sk, "○")
        open_attr = " open" if auto_open else ""
        mod_blocks.append(f"""
<details class="mod {sk}" id="mod-{_html_attr(m["key"])}"{open_attr}>
  <summary>
    <span class="ic {sk}">{mod_icon}</span>
    <span class="nm">{_html_esc(m['name'])}</span>
    <span class="vd"{v_title}>{_html_esc(v_short)}</span>
    <span class="b {sk}">{_html_esc(st)}</span>
    <a class="anchor" href="#mod-{_html_attr(m['key'])}" data-mod="mod-{_html_attr(m['key'])}"
       title="复制本模块链接">🔗</a>
    <span class="arr">▸</span>
  </summary>
  <div class="bd">
    <div class="verdict"><span class="tag">结论</span><span>{_html_esc(verdict)}</span></div>
    {explain_html}
    {metrics_html}
    {issues_html}
    {empty_note_html}
    {tech_html}
  </div>
</details>""")

    # 章节标题说明当前展开策略, 避免用户以为"没展开 = 没问题"
    problem_cnt = sum(1 for s in report["summary"].values()
                      if s in PROBLEM_STATUSES)
    if primary_modules:
        open_note = (f"共 {problem_cnt} 个问题模块 · 已展开首要问题项, "
                     f"其余点击展开")
    else:
        open_note = f"{problem_cnt} 个问题模块已展开 · 正常模块点击展开"
    modules_section = f"""
<div class="sec" id="modules"><h2><span class="icon">🔍</span>详细结果
<span class="cnt">{_html_esc(open_note)}</span></h2></div>
{"".join(mod_blocks)}"""

    # ── 主机信息 ──
    sys_pairs = [
        ("本机 IP", sys_i.get("local_ip")),
        ("默认网关", sys_i.get("gateway")),
        ("DNS", sys_i.get("dns")),
        ("公网 IP", sys_i.get("public_ip")),
    ]
    if sys_i.get("asn") or sys_i.get("geo"):
        loc = []
        if sys_i.get("geo"):
            loc.append(sys_i["geo"])
        if sys_i.get("asn"):
            loc.append(sys_i["asn"])
        sys_pairs.append(("出口位置", " / ".join(loc)))
    if sys_i.get("ipv6_public_ip"):
        sys_pairs.append(("IPv6 公网", sys_i["ipv6_public_ip"]))

    host_cards = "".join(
        f"<div class='host-card'><div class='lab'>{_html_esc(lab)}</div>"
        f"<div class='val'>{_html_esc(val) if val else '—'}</div></div>"
        for lab, val in sys_pairs
    )
    host_section = f"""
<div class="sec" id="host"><h2><span class="icon">🖥</span>主机信息</h2></div>
<div class="host-grid">{host_cards}</div>"""

    # ── 诊断标准表 (THRESHOLDS + _metrics_linkspeed 硬编码阈值, 折叠显示) ──
    standards_rows = []
    for mod_key, mod_th in THRESHOLDS.items():
        if not mod_th:
            continue
        mod_name = MODULE_MAP.get(mod_key, (mod_key,))[0]
        for metric_key, cfg in mod_th.items():
            label = cfg.get("label", metric_key)
            warn = cfg.get("warn", "—")
            err = cfg.get("err", "—")
            unit = cfg.get("unit", "")
            lower = cfg.get("lower_better", True)
            direction = "越低越差 (≥ 触发)" if lower else "越低越好 (≤ 触发)"
            standards_rows.append((mod_name, label, str(warn), str(err), unit, direction))
    # 链路速率阈值在 _metrics_linkspeed 硬编码, THRESHOLDS 里是空, 补进来
    standards_rows.append(("链路速率", "有线协商速率", "100", "1000", "Mbps", "越低越差 (≥ 触发)"))
    standards_rows.append(("链路速率", "WiFi 协商速率", "54",  "150",  "Mbps", "越低越差 (≥ 触发)"))

    std_body = "".join(
        f"<tr><td>{_html_esc(m)}</td><td>{_html_esc(l)}</td>"
        f"<td class='num'>{_html_esc(w)}</td><td class='num'>{_html_esc(e)}</td>"
        f"<td>{_html_esc(u)}</td><td>{_html_esc(d)}</td></tr>"
        for m, l, w, e, u, d in standards_rows
    )
    # v1.5.0: 判定阈值 / 评分规则属于工具内部实现, 对客户没有阅读价值
    # (还会引来"为什么异常就是扣 20 分"的疑问), 统一收进默认折叠的技术附录
    standards_section = f"""
<div class="sec" id="appendix"><h2><span class="icon">🔧</span>技术附录
<span class="cnt">默认折叠 · 供装维与技术人员查阅</span></h2></div>
<details class="collapse" data-auto-open="0"><summary>查看本次诊断的判定标准与评分口径 <span class='cnt'>{len(standards_rows)} 项指标</span></summary>
<div class="body">
  <div class='subcap'>本节是工具内部的判定口径，<b>不影响</b>上方已列出的实测数据与结论。阈值只决定状态标签（正常 / 警告 / 异常），所有原始测量值仍完整保留在各模块的「技术细节」中。</div>
  <div class='subcap' style='margin-top:10px'>判定规则: "越低越差"的指标 (延迟/丢包/重传/抖动), 超过<span class='kw warn'>警告阈值</span>标 ⚠️ 警告, 超过<span class='kw err'>异常阈值</span>标 ❌ 异常; "越高越好"的指标 (速率/TCP 可达数), 低于警告阈值标警告, 低于异常阈值标异常。所有阈值集中维护在 <code>THRESHOLDS</code>, 链路速率另在 <code>_metrics_linkspeed</code> 硬编码。</div>
  <table class='tbl std'>
    <thead><tr><th>模块</th><th>指标</th><th>警告阈值</th><th>异常阈值</th><th>单位</th><th>判定方向</th></tr></thead>
    <tbody>{std_body}</tbody>
  </table>
  <div class='subcap' style='margin-top:12px'>评分规则 (健康分是用于快速排序问题优先级的规则分, 不是统计意义上的网络质量评分): 起始 100 分, 异常 -20/项, 错误 -30/项, 警告 -2/项, 未检测不扣分。<br>豁免模块 (不参与扣分): iperf3(未配置非故障), IPv6(可选), VPN/虚拟网卡(环境特性), NAT类型(运营商侧)。等级: A≥90 优秀, B≥75 良好, C≥60 一般, D≥40 欠佳, F&lt;40 严重。</div>
</div>
</details>"""

    # ── CSS (方案 A: 晨雾浅色仪表盘) ──
    CSS = """
*{box-sizing:border-box;margin:0;padding:0;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.skip-link{position:absolute;left:-9999px;top:0;z-index:9999;background:#0a1628;color:#fff;padding:8px 16px;text-decoration:none;border-radius:0 0 8px 0}
.skip-link:focus{left:0}
@media (prefers-reduced-motion: reduce){
*{animation:none!important;transition:none!important}
}
/* 报告需可离线打开: 全部使用系统字体, 不引入任何在线资源 */
body{background:#eef1f6;color:#1e293b;font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;padding-bottom:60px}
/* ── 左侧浮动导航 ── */
.nav{position:fixed;left:18px;top:18px;bottom:18px;width:236px;background:#fff;border:1px solid #e6e9f0;border-radius:18px;padding:18px 14px;overflow-y:auto;z-index:50;box-shadow:0 8px 28px -14px rgba(15,23,42,.16)}
.nav::-webkit-scrollbar{width:4px}.nav::-webkit-scrollbar-thumb{background:#d7dce6;border-radius:2px}
.nav .logo{display:flex;align-items:center;gap:9px;padding:2px 6px 16px;border-bottom:1px solid #eef1f5;margin-bottom:12px}
.nav .logo .mark{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#7ab3f5,#2563eb);position:relative;flex:none}
.nav .logo .mark::after{content:'';position:absolute;inset:7px;border:2px solid rgba(255,255,255,.9);border-radius:4px}
.nav .logo b{font-size:15px;letter-spacing:.3px;display:block}
.nav .logo span{font-size:10.5px;color:#94a3b8;display:block;font-weight:500}
.nav .g{font-size:10.5px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;padding:10px 8px 5px}
.nav a{display:flex;align-items:center;gap:9px;padding:6.5px 10px;border-radius:9px;color:#1e293b;text-decoration:none;font-size:12.8px;line-height:1.3}
.nav a .st{width:7px;height:7px;border-radius:50%;flex:none}
.nav a:hover{background:#f4f6fa}
.nav a.on{background:#dbeafe;color:#1d4ed8;font-weight:600}
.nav .grp{margin:8px 0 2px;font-size:11px;color:#94a3b8;padding:4px 10px 2px;display:flex;align-items:center;gap:6px}
.nav .grp::after{content:'';flex:1;height:1px;background:#eef1f5}
.nav .mods a{padding:5px 10px 5px 26px;font-size:12.3px}
.nav .foot{margin-top:14px;padding:10px 8px 2px;border-top:1px solid #eef1f5;font-size:10.5px;color:#94a3b8;line-height:1.7}
/* ── 主区 ── */
.main{margin-left:282px;margin-right:24px;max-width:1060px}
/* ── 头部 hero ── */
.hero{background:#fff;border:1px solid #e6e9f0;border-radius:22px;padding:30px 36px;margin-top:18px;display:flex;gap:36px;align-items:center;box-shadow:0 10px 34px -18px rgba(15,23,42,.2)}
.hero h1{font-size:26px;font-weight:800;letter-spacing:.3px}
.hero .app{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.hero .app .mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,#7ab3f5,#2563eb);position:relative}
.hero .app .mark::after{content:'';position:absolute;inset:8px;border:2px solid #fff;border-radius:4px}
.hero .app b{font-size:16px}
.hero .ver{font-size:11px;color:#3b82f6;background:#dbeafe;padding:1px 9px;border-radius:999px;font-weight:600}
.hero .sub{font-size:12.5px;color:#64748b;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
/* v1.9.4: 健康分数描述(verdict) + 生成时间一行过长会在 hero 卡片右侧
   强制换行成两行(被 gauge 132px+gap 36px 挤到宽度 < 文字), 与健康卡
   "两行观感"同类 — 用 nowrap + ellipsis 截断次要时间戳, 保留 verdict */
.hero .meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.hero .meta span{font-size:12px;color:#64748b;background:#f4f6fa;border:1px solid #e6e9f0;border-radius:999px;padding:2.5px 11px;font-family:Cascadia Mono,Consolas,monospace}
.hero .meta span b{color:#1e293b;font-weight:600}
/* 分数环形 */
.gauge{position:relative;width:132px;height:132px;flex:none;margin-left:auto}
.gauge svg{transform:rotate(-90deg)}
.gauge .track{fill:none;stroke:#eef1f6;stroke-width:11}
.gauge .bar{fill:none;stroke-width:11;stroke-linecap:round}
.gauge .in{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px}
.gauge .num{font-size:38px;font-weight:900;color:#1e293b;font-variant-numeric:tabular-nums;line-height:1}
.gauge .lbl{font-size:12px;font-weight:700;color:#b45309;background:#fef3c7;padding:1px 10px;border-radius:999px}
/* 信息条 */
/* gap 作用于 .sep 两侧: 10px+1px+10px≈21px 视觉间距; 生成时间与 hero/页脚重复, 不再在此显示 */
.band{background:linear-gradient(90deg,#0f2a52,#1d4ed8);color:#e2ebfb;border-radius:16px;padding:14px 24px;margin:12px 0 22px;display:flex;gap:6px 10px;flex-wrap:wrap;align-items:center;font-size:12.5px}
.band b{color:#fff}
.band .sep{width:1px;height:14px;background:rgba(255,255,255,.25)}
/* 分区标题 */
.sec{margin:34px 0 12px}
.sec h2{font-size:17px;font-weight:800;display:flex;align-items:center;gap:10px;color:#111827}
.sec h2 .icon{width:26px;height:26px;border-radius:8px;background:#e0e7ff;color:#4338ca;display:inline-flex;align-items:center;justify-content:center;font-size:13px}
.sec h2 .extra-count{font-size:12px;font-weight:400;color:#64748b;margin-left:6px}
.sec h2 .cnt{font-size:11.5px;color:#94a3b8;font-weight:500;margin-left:auto}
/* 待办问题 */
.todo{background:#fff;border:1px solid #e6e9f0;border-radius:16px;padding:6px 22px 14px}
.todo.ok{background:linear-gradient(180deg,#f0fdf4,#f7fee7);border-color:#bbf7d0}
.todo-head{font-size:15px;font-weight:700;color:#991b1b;margin-bottom:12px}
.todo.ok .todo-head{color:#166534}
/* v1.9.4: "所有核心检测通过" 分支的 .impact 在 .todo 内(非 .issue 内), 旧
   .issue .impact 规则匹配不到, 文字无绿底样式显得"第二行无样式像空白" */
.todo.ok .impact{color:#166534;background:#f0fdf4;padding:8px 12px;border-radius:6px;font-size:12.5px;line-height:1.7;margin-top:4px}
.issue{padding:13px 0;border-top:1px dashed #fecaca}
.issue:first-of-type{border-top:none;padding-top:14px}
.issue.ok{border-top-color:#bbf7d0}
.issue h3{font-size:14px;font-weight:700;color:#7f1d1d;display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding-bottom:2px}
.issue.ok h3{color:#166534}
.issue .sev{display:inline-block;padding:2px 10px;border-radius:999px;font-size:10.5px;font-weight:700;background:#dc2626;color:#fff;flex:none}
.issue.warn .sev{background:#ea580c}
.issue.info .sev{background:#64748b}
.issue .meta{font-size:11.5px;color:#94a3b8;margin:2px 0 4px}
.issue .impact{font-size:12.5px;color:#991b1b;margin:4px 0 6px;padding:6px 10px;background:#fef2f2;border-radius:6px;line-height:1.7}
.issue.ok .impact{color:#166534;background:#f0fdf4}
.issue .action{font-size:12.5px;color:#0c4a6e;padding:7px 12px;background:#f0f9ff;border-left:3px solid #0284c7;border-radius:0 8px 8px 0;line-height:1.7}
.issue.consult{border-top:1px dashed #fecaca}
/* 统计卡 */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:12px;margin-bottom:8px}
.stats-caption{text-align:center;font-size:11.5px;color:#94a3b8;margin-bottom:24px}
.stat-card{background:#fff;border:1px solid #e6e9f0;border-radius:14px;padding:14px 8px;text-align:center}
.stat-card .count{font-size:30px;font-weight:800;font-variant-numeric:tabular-nums}
.stat-card.ok .count{color:#16a34a}.stat-card.warn .count{color:#d97706}.stat-card.err .count,.stat-card.danger .count{color:#dc2626}.stat-card.timeout .count{color:#334155}.stat-card.info .count{color:#6b7280}
.stat-card .label{font-size:11.5px;color:#94a3b8;margin-top:2px}
/* 图表区 */
.charts{display:grid;grid-template-columns:1.1fr .9fr;gap:14px}
.chart{background:#fff;border:1px solid #e6e9f0;border-radius:16px;padding:18px 20px}
.chart h4{font-size:13px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px;color:#1e293b}
.chart h4 .tag{font-size:10px;background:#eef2ff;color:#4338ca;border-radius:6px;padding:1px 8px;font-weight:600;margin-left:auto}
.chart .cap{font-size:11px;color:#94a3b8;margin-top:8px}
.chart.wide{grid-column:1/-1}
/* 检测结果一览 */
.overview{background:#fff;border:1px solid #e6e9f0;border-radius:16px;overflow:hidden}
.overview ul{list-style:none}
.overview li{border-bottom:1px solid #f1f5f9;font-size:13.5px}
.overview li:last-child{border-bottom:none}
.overview li a{padding:9px 20px;display:flex;align-items:center;gap:12px;color:inherit;text-decoration:none;line-height:1.4}
.overview li a:hover{background:#f8fafc}
.overview li a:hover .name{color:#2563eb}
.overview .name{font-weight:600;min-width:110px;color:#0f172a;line-height:1.4}
.overview .verdict{color:#475569;flex:1;font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;line-height:1.4}
.overview .badge{padding:2px 11px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.5px;flex:none;line-height:1.4}
.badge.ok,.b.ok{background:#dcfce7;color:#15803d}
.badge.warn,.b.warn{background:#fef3c7;color:#9a3412}
.badge.err,.b.err{background:#fee2e2;color:#991b1b}
.badge.fatal,.b.fatal{background:#fecaca;color:#7f1d1d}
.badge.idle,.b.idle{background:#e2e8f0;color:#475569}
.badge.timeout,.b.timeout{background:#cbd5e1;color:#1e293b}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;flex:none}
.dot.ok{background:#16a34a}.dot.warn{background:#d97706}.dot.err{background:#dc2626}.dot.fatal{background:#7f1d1d}.dot.timeout{background:#334155}.dot.idle{background:#94a3b8}
/* 模块卡 (details 折叠, 问题模块自动展开) */
details.mod{background:#fff;border:1px solid #e6e9f0;border-radius:16px;margin-bottom:12px;overflow:hidden;box-shadow:0 1px 2px rgba(15,23,42,.04);scroll-margin-top:16px}
details.mod[open]{border-color:#c7cbd8}
details.mod>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 20px;user-select:none}
details.mod>summary::-webkit-details-marker{display:none}
details.mod>summary .ic{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px;flex:none}
details.mod.ok>summary .ic{background:#dcfce7;color:#15803d}
details.mod.warn>summary .ic{background:#fef3c7;color:#b45309}
details.mod.err>summary .ic{background:#fee2e2;color:#b91c1c}
details.mod.fatal>summary .ic{background:#7f1d1d;color:#fff}
details.mod.timeout>summary .ic{background:#334155;color:#fff}
details.mod.idle>summary .ic{background:#f1f5f9;color:#64748b}
details.mod>summary .nm{font-size:14.5px;font-weight:700;flex:none}
details.mod>summary .vd{font-size:12px;color:#64748b;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
details.mod>summary .b{font-size:11px;font-weight:700;padding:2px 11px;border-radius:999px;flex:none}
details.mod>summary .arr{color:#94a3b8;font-size:11px;transition:transform .15s}
details.mod[open]>summary .arr{transform:rotate(90deg)}
/* 🔗 复制模块链接按钮 */
details.mod>summary .anchor{flex:none;font-size:11px;text-decoration:none;color:#94a3b8;padding:2px 7px;border-radius:999px;opacity:.35;transition:opacity .12s;line-height:1.4;cursor:pointer}
details.mod:hover>summary .anchor,details.mod>summary .anchor:focus-visible,details.mod>summary .anchor.copied{opacity:1}
details.mod>summary .anchor:hover{color:#2563eb;background:#eef2ff}
details.mod>summary .anchor.copied{color:#15803d;background:#dcfce7}
details.mod>.bd{padding:4px 22px 20px;border-top:1px dashed #e6e9f0}
details.mod .verdict{font-size:13.5px;color:#1e293b;padding:12px 0 4px;line-height:1.7}
details.mod .verdict .tag{display:inline-block;font-size:10.5px;font-weight:700;background:#eef2ff;color:#4338ca;border-radius:5px;padding:1px 8px;margin-right:8px}
.explain{font-size:12px;line-height:1.7;color:#64748b;background:#f8fafc;border-left:3px solid #cbd5e1;padding:7px 12px;border-radius:0 6px 6px 0;margin:4px 0 12px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0 8px}
.metric{background:#f8fafc;border:1px solid #e6e9f0;border-radius:9px;padding:9px 13px;display:flex;flex-direction:column;align-items:flex-start;gap:3px;min-width:0}
.metric .v{font-size:15px;font-weight:700;font-family:Cascadia Mono,Consolas,monospace;text-align:left;max-width:100%;overflow-wrap:break-word}
.metric .lab{font-size:11.5px;color:#64748b;overflow-wrap:break-word;white-space:normal;line-height:1.45;max-width:100%}
.metric .v.ok{color:#15803d}.metric .v.warn{color:#c2410c}.metric .v.err{color:#b91c1c}.metric .v.info{color:#64748b}.metric .v.idle{color:#94a3b8}
.metric[data-hint]{cursor:pointer}
.metric.show-hint::after{content:attr(data-hint);display:block;font-size:11px;color:#475569;background:#eef2ff;border-radius:4px;padding:4px 8px;margin-top:4px;line-height:1.5}
.metric .hint{font-size:11px;color:#b45309;font-weight:400;display:block;margin-top:2px;line-height:1.45}
.impact-line{background:#fef2f2;border-left:3px solid #dc2626;padding:6px 12px;border-radius:0 6px 6px 0;font-size:12.5px;color:#7f1d1d;margin:8px 0}
.impact-line.warn{background:#fffbeb;border-left-color:#d97706;color:#78350f}.impact-line.info{background:#f1f5f9;border-left-color:#94a3b8;color:#475569;font-size:12px}
.action-line{background:#f0f9ff;border-left:3px solid #0284c7;padding:6px 12px;border-radius:0 6px 6px 0;font-size:12.5px;color:#0c4a6e;margin:4px 0 8px;line-height:1.6}
details.collapse{margin-top:10px;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:10px}details.collapse[data-auto-open="1"]{border-style:solid;border-color:#cbd5e1}
details.collapse summary{padding:9px 14px;font-size:12px;color:#64748b;cursor:pointer;font-weight:600;user-select:none;list-style:none;display:flex;align-items:center;gap:6px}
details.collapse summary::-webkit-details-marker{display:none}
details.collapse summary::before{content:"▸";color:#94a3b8;transition:transform .15s;display:inline-block}
details.collapse[open] summary::before{transform:rotate(90deg)}
details.collapse .cnt{background:#e2e8f0;color:#475569;border-radius:999px;font-size:10.5px;padding:1px 8px;margin-left:6px;font-weight:600}
details.collapse .body{padding:4px 14px 12px;font-size:12px;color:#475569;line-height:1.7}
details.collapse .subcap{font-size:12px;font-weight:700;color:#475569;margin:10px 0 4px}
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin-top:4px;border-radius:4px}
.tbl-wrap::-webkit-scrollbar{height:6px}
.tbl-wrap::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}
details.collapse table{width:100%;border-collapse:collapse}
details.collapse table.tbl{min-width:520px}
details.collapse table.tbl.kv{min-width:0}
details.collapse th{background:#e2e8f0;color:#334155;text-align:left;padding:5px 10px;font-weight:600;font-size:11.5px;white-space:nowrap}
details.collapse td{padding:4px 10px;border-top:1px solid #e2e8f0;font-family:Cascadia Mono,Consolas,monospace;font-size:11.5px;white-space:normal;word-break:break-word;vertical-align:top}
details.collapse td.k{width:35%;color:#64748b;background:#f8fafc;white-space:normal}
details.collapse p.mono{font-family:Cascadia Mono,Consolas,monospace;background:#f1f5f9;padding:6px 10px;border-radius:4px;word-break:break-all}
details.collapse p.muted{color:#94a3b8;font-size:11.5px;margin-top:6px}
/* 主机信息 */
.host-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}
.host-card{background:#fff;border:1px solid #e6e9f0;border-radius:12px;padding:12px 16px}
.host-card .lab{font-size:11px;color:#94a3b8;margin-bottom:3px;font-weight:500}
.host-card .val{font-size:13px;font-weight:600;font-family:Cascadia Mono,Consolas,monospace;color:#0f172a;cursor:pointer;word-break:break-all}.host-card .val:hover{color:#2563eb;background:#f1f5f9}.host-card .val.copied{color:#16a34a !important}
/* 诊断标准表 */
.tbl.std{font-size:12px}
.tbl.std th{background:#1e293b;color:#f1f5f9;font-weight:600;padding:7px 10px}
.tbl.std td{padding:6px 10px;border-top:1px solid #e2e8f0;vertical-align:top}
.tbl.std td.num{font-family:Cascadia Mono,Consolas,monospace;text-align:center;font-weight:600;color:#1e293b}
.tbl.std tbody tr:nth-child(odd){background:#f8fafc}
.kw{display:inline-block;padding:0 6px;border-radius:4px;font-weight:600;font-size:11.5px}
.kw.warn{background:#fed7aa;color:#9a3412}
.kw.err{background:#fecaca;color:#991b1b}
details.collapse .subcap code{background:#fff;padding:1px 6px;border-radius:3px;border:1px solid #cbd5e1;font-size:11.5px;color:#475569}
@media(max-width:960px){.nav{display:none}.main{margin:0 14px}.hero{flex-wrap:wrap}.gauge{margin:0}.charts{grid-template-columns:1fr}}
@media print{body{background:#fff;padding:0;font-size:12px}.nav,.sec .cnt,.chart .tag{display:none}.main{margin:0}.hero,.stat-card,.chart,.mod,.todo,.overview,.host-card{box-shadow:none}.hero{background:#f8fafc !important;border:1px solid #ddd !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.mod,.host-card,.todo{break-inside:avoid}details.mod>summary .arr,details.collapse>summary::before{display:none}details.mod>summary{cursor:default}details.mod,details.collapse{border-style:solid}}
footer{text-align:center;color:#94a3b8;font-size:12px;margin-top:36px;padding-top:20px;border-top:1px solid #e6e9f0}
""" + _DIAGNOSIS_CSS  # 阶段 C · v1.3.0: 根因摘要 CSS

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0a1628">
<title>{_html_esc(report['app'])} 诊断报告</title>
<style>{CSS}</style>
</head>
<body>
<a href="#main-content" class="skip-link">跳到主要内容</a>
<nav class="nav" aria-label="报告导航">
  <div class="logo"><div class="mark"></div>
    <div><b>{_html_esc(report['app'])}</b><span>网络诊断报告</span></div></div>
  {nav_html}
  <div class="foot">v{_html_esc(report['version'])} · 生成于 {_html_esc(g)}<br>点条目跳转到对应模块</div>
</nav>
<div class="main">
<main id="main-content">
{hero}
{diagnosis_section}
{band_html}
{todo_section}
{stats_section}
{charts_section}
{overview_section}
{modules_section}
{host_section}
{standards_section}
</main>
<footer>由 {_html_esc(report['app'])} v{_html_esc(report['version'])} 自动生成 · {_html_esc(g)}</footer>
</div>
<script>
// 左侧导航滚动高亮
(function(){{
  var links = document.querySelectorAll('.nav a[href^="#"]');
  var map = {{}};
  // 只收集导航目标 id (mod-* 与固定分区), 避免 SVG 渐变 id 等混入;
  // offsetTop 不是数字的直接跳过 (SVG 内部元素没有 offsetTop)
  var NAV_IDS = ['overview', 'todo', 'stats', 'charts', 'list'];
  document.querySelectorAll('[id]').forEach(function(el){{
    if (!el.id || typeof el.offsetTop !== 'number') return;
    if (el.id.indexOf('mod-') !== 0 && NAV_IDS.indexOf(el.id) < 0) return;
    map[el.id] = el;
  }});
  window.addEventListener('scroll', function(){{
    // 阈值须小于折叠模块行的间距 (约 76px), 否则密集列表会提前高亮到下一行
    var y = window.scrollY + 40, cur = null;
    Object.keys(map).forEach(function(id){{
      if (map[id].offsetTop <= y) cur = id;
    }});
    links.forEach(function(a){{
      a.classList.toggle('on', a.getAttribute('href') === '#' + cur);
    }});
  }}, {{passive:true}});
}})();
// 指标卡点击展开说明 (触摸设备无 hover; 桌面点击也可用)
(function(){{
  document.querySelectorAll('.metric[data-hint]').forEach(function(el){{
    el.addEventListener('click', function(){{
      el.classList.toggle('show-hint');
    }});
  }});
}})();
// 复制工具 (全局): clipboard API 优先, 失败回退 execCommand; done 为成功回调
function fallbackCopy(txt, done){{
  var ta = document.createElement('textarea');
  ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try {{ document.execCommand('copy'); }} catch(e) {{}}
  document.body.removeChild(ta);
  if (done) done();
}}
function copyText(txt, done){{
  if (navigator.clipboard && navigator.clipboard.writeText){{
    navigator.clipboard.writeText(txt).then(done).catch(function(){{ fallbackCopy(txt, done); }});
  }} else {{
    fallbackCopy(txt, done);
  }}
}}
// IP/MAC 值点击复制
(function(){{
  document.querySelectorAll('.host-card .val').forEach(function(el){{
    el.addEventListener('click', function(){{
      var txt = el.textContent.trim();
      if (!txt || txt === '—') return;
      copyText(txt, function(){{
        var orig = el.textContent;
        el.textContent = '✓ 已复制';
        el.classList.add('copied');
        setTimeout(function(){{ el.textContent = orig; el.classList.remove('copied'); }}, 1200);
      }});
    }});
    el.title = '点击复制: ' + el.textContent.trim();
  }});
}})();
// v1.5.0 通用复制按钮: data-copy 直接取短文本, data-copy-from 从目标元素读长文本
(function(){{
  document.querySelectorAll('.copy-btn[data-copy], .copy-btn[data-copy-from]').forEach(function(btn){{
    btn.addEventListener('click', function(e){{
      e.preventDefault();
      var txt = btn.getAttribute('data-copy') || '';
      if (!txt) {{
        var src = document.getElementById(btn.getAttribute('data-copy-from') || '');
        txt = src ? src.textContent : '';
      }}
      if (!txt) return;
      copyText(txt, function(){{
        var orig = btn.getAttribute('data-orig-text') || btn.textContent;
        btn.setAttribute('data-orig-text', orig);
        btn.textContent = '✓ 已复制';
        btn.classList.add('done');
        setTimeout(function(){{
          btn.textContent = orig;
          btn.classList.remove('done');
        }}, 1200);
      }});
    }});
  }});
}})();
// 模块卡 🔗 按钮: 复制带锚点的报告链接; preventDefault 避免 <summary> 折叠与页面跳转
(function(){{
  document.querySelectorAll('.mod > summary a.anchor').forEach(function(a){{
    a.addEventListener('click', function(e){{
      e.preventDefault();
      var id = a.getAttribute('href').slice(1);
      copyText(location.href.split('#')[0] + '#' + id, function(){{
        a.classList.add('copied');
        setTimeout(function(){{ a.classList.remove('copied'); }}, 1200);
      }});
      location.hash = id;   // 触发下方 hashchange: 展开卡片并定位
    }});
  }});
}})();
// 锚点跳转: 浏览器只负责滚动到折叠卡, 内容需先展开才能看到
(function(){{
  function openByHash(){{
    var h = decodeURIComponent((location.hash || '').slice(1));
    if (!h) return;
    var t = document.getElementById(h);
    if (t && t.tagName === 'DETAILS' && !t.open) t.open = true;
  }}
  window.addEventListener('hashchange', openByHash);
  window.addEventListener('DOMContentLoaded', openByHash);
}})();
// 打印/另存 PDF: 闭合的 <details> 无法靠 CSS 强制展开 (需 [open] 属性或 JS),
// 打印前全部展开、打印后恢复原状 — 保证纸质留档包含技术细节全文
(function(){{
  var touched = [];
  window.addEventListener('beforeprint', function(){{
    touched = [];
    document.querySelectorAll('details').forEach(function(d){{
      if (!d.open){{ d.open = true; touched.push(d); }}
    }});
  }});
  window.addEventListener('afterprint', function(){{
    touched.forEach(function(d){{ d.open = false; }});
    touched = [];
  }});
}})();
</script>
</body>
</html>"""


# ============================================================
# JSON 报告 (技术员/脚本用, 包含 raw 原始数据 + 阈值定义)
# ============================================================
def _json_default(o):
    """JSON 序列化时处理 datetime 等不可序列化对象。"""
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(f"Type {type(o).__name__} not JSON serializable")


def render_report_json(report, indent=2):
    """渲染 JSON 报告 (技术员/脚本用)。

    顶层结构对齐 schema/netpulse-result-v1.1.json (阶段 D · D1):
    app / version / schema_version / generated_at / system / health /
    counts / summary / diagnosis / modules 为必填字段, 可直接用仓库自带的
    schema 文件校验。meta 为旧解析器兼容视图 (schema 允许未知字段)。

      - health: 健康评分 (score, grade, label, verdict) + counts
      - modules: 客户视图 (verdict + key_metrics + issues)
      - diagnosis: 根因分析 (root_causes + 置信度, 阶段 C 引入)
      - tech.raw_results: 每个模块的原始 result 字典 (含 30 个 RTT 全序列等)
      - tech.thresholds: 阈值定义 (为啥这个值是"异常"的依据)
      - tech.module_presentation: 每个模块的客户视图配置 key
    """
    if not report:
        return "{}"
    out = {
        "app": report["app"],
        "version": report["version"],
        "schema_version": report["schema_version"],
        "generated_at": report["generated_at"],
        "system": report["system"],
        "health": report["health"],
        "counts": report["counts"],
        "exempt_count": report.get("exempt_count", 0),
        "summary": report["summary"],
        "diagnosis": report["diagnosis"],
        "modules": report["modules"],
        "tech": report["tech"],
        # 兼容视图: v1.4.0 之前的消费方读 meta.host / meta.app
        "meta": {
            "app": report["app"],
            "version": report["version"],
            "generated_at": report["generated_at"],
            "host": report["system"],
        },
    }
    return json.dumps(out, ensure_ascii=False, indent=indent, default=_json_default)


# 老的 render_report_text 保留, 但 export_report 默认不再导出
# (客户报告走 HTML/JSON, TXT 是 legacy 模式; 仍可手工调用)
# 已存在的 render_report_text / render_report_html 保留代码, 不再被 export_report 调用


def _report_dir():
    """报告默认保存目录: <程序所在目录>/reports/YYYY-MM-DD/ (自动创建)。

    PyInstaller 打包后 ``__file__`` 指向临时解压目录, 故使用 ``sys.executable`` 解析。
    若首选目录不可写 (例如 EXE 装在 ``C:\\Program Files\\`` 只读位置),
    自动回退到 ``%USERPROFILE%\\NetPulse\\reports\\``。
    """
    if getattr(sys, "frozen", False):
        base = os.path.dirname(os.path.abspath(sys.executable))
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(base, "reports", datetime.now().strftime("%Y-%m-%d"))
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except OSError:
        # 回退: 用户主目录下的 NetPulse 目录
        fallback = os.path.join(
            os.path.expanduser("~"), "NetPulse", "reports",
            datetime.now().strftime("%Y-%m-%d"))
        os.makedirs(fallback, exist_ok=True)
        return fallback


def _normalize_report_path(path):
    """仅给文件名时, 自动放入日期文件夹; 含目录则尊重原路径。"""
    if os.path.dirname(path) in ("", "."):
        return os.path.join(_report_dir(), os.path.basename(path))
    return path


def export_report(path, rule_filter=None, report=None):
    """按扩展名导出客户版报告: .html / .json。

    rule_filter: 场景 profile id (可选, v1.6.1), 透传 build_report() —
                 场景导出与完成屏保持同一规则集。
    report:      预构建的报告 dict (可选, v1.6.1) — 场景路径传入以复用
                 同一份构建结果, 避免重复跑诊断 (审查 #8)。

    客户版设计:
      - .html → 客户版 HTML (健康分 + 问题清单 + 关键指标 + 折叠技术细节)
      - .json → 技术员/脚本用 (含 raw 原始数据 + 阈值定义)

    PDF 直接导出已移除; 需要纸质留档时, 用浏览器打开 HTML 后 Ctrl+P
    打印或另存为 PDF (打印样式已内置: 技术细节全部展开、去阴影配色)。

    老的 .txt 报告 (拍平所有数据) 已废弃, 导出 .txt 现在会返回错误提示。
    如需旧格式, 请手动调用 render_report_text()。
    """
    path = _normalize_report_path(path)
    if report is None:
        report = build_report(rule_filter=rule_filter)
    if not report:
        return "尚无诊断数据，无法生成报告（请先运行诊断）"
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in (".html", ".htm"):
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_report_html_customer(report))
            return None
        elif ext == ".json":
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_report_json(report))
            return None
        elif ext == ".pdf":
            return ("PDF 直接导出已移除。请导出 .html 后用浏览器打开, "
                    "Ctrl+P 打印或另存为 PDF。")
        elif ext == ".txt":
            return "TXT 客户版未提供, 改用 --export report.html / .json。"
        else:
            return f"不支持的扩展名: {ext} (支持: .html / .json)"
    except Exception as e:
        return f"导出失败: {e}"


def prompt_export_report():
    """交互菜单跑完后, 询问是否将本次诊断导出为报告文件。

    默认直接生成 HTML (最常用格式), 一次回车即可;
    输入 t 改 TXT(会提示不支持), 其他输入均按默认 HTML 处理。
    """
    if not LAST_RUN:
        return
    try:
        ans = input(_c("  生成诊断报告? [Enter=HTML / t=TXT / N=不导出] ",
                       C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if ans in ("n", "no", "q", "quit"):
        return
    ext = ".txt" if ans in ("t", "txt") else ".html"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"netdiag_report_{ts}{ext}"
    err = export_report(name)
    if err:
        print(_c(f"  ✗ {err}", C_RED))
    else:
        print(_c(f"  ✓ 报告已导出: {os.path.abspath(_normalize_report_path(name))}", C_GREEN))


def parse_choice(choice):
    """解析交互菜单输入 -> keys 列表; 无效返回 None。
    支持: 数字 (空格分隔多选)、0/all/* (全部, 压力级模块除外)、分类字母 a/b/c、
    模块 key、模块中文名。
    严格模式: 任一 token 非法即整体拒绝。
    """
    choice = (choice or "").strip()
    if choice == "":
        return None
    if choice.lower() in ("0", "all", "*"):
        print(_c(_stress_excluded_hint(), C_GRAY))
        return all_module_keys()
    return _parse_keys(choice.split(), strict=True)


def _format_error_for_user(exc):
    """把异常转成 (客户语言一句话, 工程师细节) 两段 (PR-C · v1.6.0)。

    仅场景路径 try/except 包装用; CLI 全量输出不受影响。
    """
    name = type(exc).__name__
    msg = str(exc) or name
    detail = f"[{name}] {msg}"
    if isinstance(exc, KeyboardInterrupt):
        return ("已中断本次检测。", detail)
    if isinstance(exc, PermissionError):
        return ("权限不足：无法执行该检测（请以管理员身份重新运行）", detail)
    if isinstance(exc, socket.gaierror):
        return ("DNS 解析失败：无法解析域名（请检查 DNS 设置或联系运营商）", detail)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ("网络超时：请求响应太慢（可能是网络拥堵或运营商故障）", detail)
    return ("检测过程中出错（请重试；连续失败请联系技术支持）", detail)


def _known_folder_desktop():
    """SHGetKnownFolderPath(FOLDERID_Desktop) 解析真实桌面路径 (v1.6.1)。

    一次系统调用覆盖 OneDrive 重定向与本地化目录名 (中文 Windows 的
    重定向桌面是 OneDrive\\桌面, 只探测 OneDrive\\Desktop 会漏); 失败
    (非 Windows / 输出重定向 / API 异常) 返回 None, 由调用方走候选探测。
    """
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        class _GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        # FOLDERID_Desktop {B4BFCC3A-DB2C-424C-B029-FEFE9560C1C8}
        folderid = _GUID(0xB4BFCC3A, 0xDB2C, 0x424C,
                         (ctypes.c_ubyte * 8)(0xB0, 0x29, 0xFE, 0xFE,
                                              0x95, 0x60, 0xC1, 0xC8))
        buf = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(
                ctypes.byref(folderid), 0, None, ctypes.byref(buf)) != 0:
            return None
        path = buf.value
        ctypes.windll.ole32.CoTaskMemFree(buf)
        return path or None
    except Exception:
        return None


def _desktop_netpulse_dir():
    """桌面 NetPulse 目录; 全不可用返回 None (PR-C / v1.6.1 加固)。

    优先 SHGetKnownFolderPath(FOLDERID_Desktop) — 系统直接给出真实桌面
    (含 OneDrive 重定向与中文本地化目录名); 解析失败再按候选目录探测
    (仅当 OneDrive 桌面真实存在才纳入, 避免普通环境误建 OneDrive 目录);
    都不可写则返回 None, 由调用方退化到 reports/ 目录。
    """
    cands = []
    real = _known_folder_desktop()
    if real:
        cands.append(os.path.join(real, "NetPulse"))
    base = os.environ.get("USERPROFILE") or ""
    if base:
        one_desktop = os.path.join(base, "OneDrive", "Desktop")
        if os.path.isdir(one_desktop):
            cands.append(os.path.join(one_desktop, "NetPulse"))
        one_desktop_cn = os.path.join(base, "OneDrive", "桌面")
        if os.path.isdir(one_desktop_cn):
            cands.append(os.path.join(one_desktop_cn, "NetPulse"))
        cands.append(os.path.join(base, "Desktop", "NetPulse"))
        cands.append(os.path.join(base, "桌面", "NetPulse"))
    for d in cands:
        try:
            os.makedirs(d, exist_ok=True)
            if os.access(d, os.W_OK):
                return d
        except Exception:
            continue
    return None


def _export_scene_report(profile, title, report=None):
    """场景完成后保存 HTML 报告到 桌面\\NetPulse\\, 返回 (path, err) (PR-C)。

    report: 预构建报告 dict (v1.6.1 审查 #8), 复用完成屏同一份构建结果。
    不可写时退化 _report_dir() (原 reports/ 逻辑), 与 CLI --export 无关。
    """
    if not LAST_RUN:
        return None, "尚无诊断数据"
    base = _desktop_netpulse_dir()
    if not base:
        base = _report_dir()
    # 文件名含时分秒: 纯日期命名会让同日复测静默覆盖上午的报告 (审查 #5)
    name = f"{datetime.now():%Y-%m-%d_%H%M%S}_{title}.html"
    path = os.path.join(base, name)
    err = export_report(path, rule_filter=profile, report=report)
    if err:
        return path, err
    return path, None


def _scene_summary(profile, title, diagnosis, report=None):
    """场景完成屏: 健康分 + 一句话根因结论 (复用 _print_diagnosis, PR-A/PR-C)。

    report: 预构建报告 dict (v1.6.1 审查 #8), 缺省时兜底自建。
    """
    print()
    print(_c("=" * 60, C_BLUE))
    print(_c(f"  {APP_NAME} > {title} > 检测完成", C_BOLD))
    print(_c("-" * 60, C_GRAY))
    try:
        if report is None:
            report = build_report(rule_filter=profile)
        health = (report or {}).get("health") or {}
        score = health.get("score")
        grade = health.get("grade")
        if score is not None:
            print(_c(f"  网络健康: {score} / 100" +
                     (f" （{grade}）" if grade else ""), C_BOLD))
            print()
    except Exception:
        pass
    if diagnosis is not None:
        _print_diagnosis(diagnosis)
    else:
        print(_c("  ⚠ 本次未能完成根因分析。", C_YELLOW))
    print(_c("-" * 60, C_GRAY))


def _pause_enter(msg="  按 Enter 返回主菜单..."):
    """菜单路径通用回车暂停; EOF/Ctrl+C 静默返回 (v1.6.1)。"""
    try:
        input(_c(msg, C_GRAY))
    except (EOFError, KeyboardInterrupt):
        print()


def _run_scene_monitor(install=False, pip_mirror=None):
    """[7] 持续盯障: 输入分钟数 (1-1440, 默认 10) → run_monitor_mode。"""
    print(_c("  持续盯障: 持续监测外网连通性, 找偶发掉线/抖动。", C_WHITE))
    try:
        ans = input(_c("  盯障时长（分钟, 1-1440, 默认 10）: ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    minutes = 10
    if ans:
        try:
            minutes = int(ans)
        except ValueError:
            minutes = 10
    minutes = max(1, min(1440, minutes))
    # 抓包取证菜单入口 (v1.9.6): 时长问完问一次, Enter=不开启 (与 CLI 默认一致)。
    # 不可用 (非管理员/无 Npcap) 时函数内部亮原因后直接返回 None, 不出选择题。
    # v1.9.7 PR-3: 传盯障接续参数 — 仅缺管理员权限时可一键提权重启并直接续盯
    capture_mode, capture_mb = _prompt_for_capture(
        resume_tail=["--monitor", str(minutes)])
    print(_c(f"  开始盯障 {minutes} 分钟（{minutes*60} 秒）... Ctrl+C 可提前结束", C_BOLD))
    try:
        run_monitor_mode(minutes * 60, capture_mode=capture_mode,
                         capture_mb=capture_mb)
    # (Exception, KeyboardInterrupt): Ctrl+C 是 BaseException, 只捕 Exception
    # 会把原始回溯打到客户屏幕上, _format_error_for_user 的中断文案成死分支 (审查 #4)
    except (Exception, KeyboardInterrupt) as e:
        user_msg, detail = _format_error_for_user(e)
        print(_c(f"  ✗ {user_msg}", C_RED))
        if sys.stdout.isatty():
            print(_c(f"    {detail}", C_GRAY))
    _pause_enter()


def _run_scene(profile, install=False, pip_mirror=None):
    """执行一个场景: 跑模块 → 根因 (规则过滤) → 完成屏 → 报告存桌面。

    PR-A + PR-B + PR-C 集成点。CLI --diagnose 路径不受影响。
    """
    title = SCENE_LABELS.get(profile, profile)
    keys = DIAGNOSE_PROFILES[profile]
    names = [MODULE_MAP[k][0] for k in keys if k in MODULE_MAP]
    print(_c(f"  场景「{title}」: 将检测 {len(keys)} 项 — ", C_BOLD) + "、".join(names))
    print(_c("  预计 1-3 分钟, 请稍候...", C_GRAY))
    try:
        run_diagnostics(keys, banner=False, parallel=True, max_workers=4,
                        install=install, pip_mirror=pip_mirror)
    # (Exception, KeyboardInterrupt): Ctrl+C 是 BaseException, 只捕 Exception
    # 会把原始回溯打到客户屏幕上, _format_error_for_user 的中断文案成死分支 (审查 #4)
    except (Exception, KeyboardInterrupt) as e:
        user_msg, detail = _format_error_for_user(e)
        print(_c(f"  ✗ {user_msg}", C_RED))
        if sys.stdout.isatty():
            print(_c(f"    {detail}", C_GRAY))
        _pause_enter()
        return
    # 根因分析 (PR-B: 按场景规则集评估, 避免 gaming 报 wifi 弱等无关根因)
    # v1.6.1 (审查 #8): 诊断只评一次, 完成屏/导出报告复用同一份构建结果 —
    # 屏幕与文件必然一致, 也不再重复跑全量规则评估
    diagnosis = None
    report = None
    if LAST_RUN and LAST_RUN.get("results"):
        try:
            diagnosis = _enrich_diagnosis_evidence(
                diagnose(LAST_RUN["results"], rule_filter=profile),
                LAST_RUN["results"], LAST_RUN.get("evidence"))
        except Exception:
            diagnosis = None
        try:
            report = build_report(
                rule_filter=profile,
                diagnosis=diagnosis.to_dict() if diagnosis else None)
        except Exception:
            report = None
    _scene_summary(profile, title, diagnosis, report=report)
    # 报告存桌面 (PR-C)
    path, err = _export_scene_report(profile, title, report=report)
    if err:
        print(_c(f"  ✗ 报告保存失败: {err}", C_RED))
    else:
        print(_c(f"  📄 报告已保存: {path}", C_GREEN))
    # v1.6.1: 停一拍再回菜单 — 否则完成屏 (健康分/根因/报告路径) 瞬间被清掉
    _pause_enter()


def _menu_clear():
    """清屏 (v1.6.1): 先确认 VT 可用再写 ANSI 转义, 否则退化 cls/clear。

    原实现先写转义再探返回值 — _clear_screen 只要写入不抛异常就返回
    True, VT 未启用时旧 conhost 会打出字面乱码且子进程回退永不可达
    (审查 #7)。_module_menu 的同款拷贝已收敛为本函数。
    """
    if _cli_enable_vt() and _clear_screen():
        return
    if os.name == "nt":
        try:
            subprocess.run(["cls"], shell=True, timeout=2)
        except Exception:
            pass
    else:
        try:
            subprocess.run(["clear"], timeout=2)
        except Exception:
            pass


def _perm_badge():
    """菜单标题权限徽标 (v1.9.7 PR-3): 让用户开屏就知道当前权限状态。"""
    return _c("    [管理员模式]" if _is_admin() else "    [普通权限]", C_GRAY)


def _scene_menu(install=False, pip_mirror=None):
    """场景层首页 (PR-A · v1.6.0): 中文场景标签 + 数字回车。

    返回 False = 退出程序 ([0] 退出 / [9] 高级页里退出 / Ctrl+C)。
    v1.9.7 PR-3: 标题权限徽标 + [A] 一键以管理员身份重启。
    """
    while True:
        _menu_clear()
        bar = "=" * 60
        print(_c(bar, C_BLUE))
        print(_c(f"  {APP_NAME} v{APP_VERSION}    网络诊断（场景模式）", C_BOLD)
              + _perm_badge())
        print(_c(bar, C_BLUE))
        print(_c("  请选择场景（输入数字回车）：", C_WHITE))
        print()
        print(f"    {_c('[1]', C_CYAN)} 网络很慢        {_c('[2]', C_CYAN)} 经常断网      {_c('[3]', C_CYAN)} 网页打不开")
        print(f"    {_c('[4]', C_CYAN)} 游戏卡顿        {_c('[5]', C_CYAN)} WiFi 信号差")
        print()
        print(f"    {_c('[7]', C_CYAN)} 持续盯障（输入分钟数）")
        print(f"    {_c('[9]', C_CYAN)} 高级选项（工程师用）   "
              f"{_c('[A]', C_CYAN)} 管理员模式   {_c('[0]', C_CYAN)} 退出")
        print(_c("     (管理员模式 = 以管理员身份重启, 抓包取证/Npcap 安装需要)", C_GRAY))
        print(_c("-" * 60, C_GRAY))
        try:
            choice = input(_c("  选择 [0-9A]: ", C_GREEN)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if choice in ("0", "q", "quit", "exit"):
            return False
        if choice == "a":
            # 一键提权重启: 提权成功 → sys.exit(0) (不会走到这里); 失败/取消
            # → 落回菜单继续 (不藏退路)
            _offer_elevation_relaunch(
                reason="抓包取证、Npcap 安装等功能需要管理员权限")
            continue
        if choice == "9":
            # 高级页 (原模块清单菜单) 里退出 → 整个程序退出
            if not _module_menu(install=install, pip_mirror=pip_mirror):
                return False
            continue
        if choice == "7":
            _run_scene_monitor(install=install, pip_mirror=pip_mirror)
            continue
        if choice in SCENE_MENU_KEYS:
            _run_scene(SCENE_MENU_KEYS[choice], install=install,
                       pip_mirror=pip_mirror)
            continue
        print(_c("  无效选择, 请重新输入。", C_YELLOW))
        try:
            input(_c("  按 Enter 继续...", C_GRAY))
        except (EOFError, KeyboardInterrupt):
            return False


def interactive_menu(install=False, pip_mirror=None):
    """交互式场景菜单 (cmd 窗口, v1.6.0)。

    无参数启动 → 场景层 (中文场景标签 + 数字回车);
    [9] 高级选项 = 原模块清单菜单 (工程师用), 行为与 v1.5.x 一致。

    install: 是否允许在交互过程中自动安装缺失依赖
             (与 CLI --install 联动)。
    pip_mirror: 透传给 ensure_scapy。

    并发策略:
      - 选 0 / 选多个模块 -> 默认并发 (跟 CLI `all --parallel` 对齐,
        选全部时绝大多数用户想要快而不是看实时进度)
      - 选单模块 -> 走顺序, 让 TTY 实时进度行 (\\r\\033[K 刷新) 正常显示
      - run_diagnostics 内部 `parallel and len(keys) > 1` 会自动归一化

    测速模块: 交互菜单默认启用 Ookla 官方测速 (上海电信节点 3633),
    无需 --speedtest-net; CLI 模式仍需显式加 --speedtest-net。
    """
    # 交互菜单: 默认启用 Ookla 官方测速 (上海电信节点, 避免自动选点偏海外)
    # CLI 模式不受影响 (CLI 需显式 --speedtest-net)
    SPEEDTEST_CONFIG["use_speedtest_net"] = True
    if not SPEEDTEST_CONFIG.get("ookla_server_id"):
        SPEEDTEST_CONFIG["ookla_server_id"] = OOKLA_DEFAULT_SERVER_ID
    if not _scene_menu(install=install, pip_mirror=pip_mirror):
        return


def _module_menu(install=False, pip_mirror=None):
    """原模块清单菜单 (v1.6.0 起为场景层 [9] 高级选项)。

    行为与 v1.5.x 一致 (模块编号 / 分类 / 0 全部 / m 盯障 / e 导出 / q 退出);
    返回语义 (v1.9.3): r = 返回场景层主菜单 → True; q / Ctrl+C / EOF → False
    (通知场景层结束整个程序)。
    """
    while True:
        _menu_clear()
        bar = "=" * 60
        print(_c(bar, C_BLUE))
        print(_c(f"  {APP_NAME} v{APP_VERSION}    命令行网络诊断", C_BOLD)
              + _perm_badge())
        print(_c(bar, C_BLUE))
        print(_c("  工程师模式 (模块级诊断)。运行完成后可返回场景模式主菜单。", C_WHITE))
        idx = 0
        # 全局模块名最大显示宽, 跨分类统一 (保证所有 cell 内的模块名
        # 右端对齐到同一显示列, 行内/行间都齐)
        all_names = [MODULE_MAP[k][0]
                     for _cat_keys in (kc[1] for kc in MODULE_CATEGORIES)
                     for k in _cat_keys]
        name_max_w_global = max((_disp_width(n) for n in all_names), default=0)
        for ci, (cat_name, keys, desc) in enumerate(MODULE_CATEGORIES):
            if ci > 0:
                print()
            letter = MODULE_NAME_LETTER.get(cat_name, "")
            tag = _c(f"[{letter}]", C_CYAN) if letter else ""
            print(_c(f"  {tag} {cat_name}", C_BOLD) +
                  _c(f"  {desc}", C_GRAY))
            cells = []
            # 模块名按显示宽 pad 到全局一致 (e.g. "链路速率" 8 宽 vs
            # "LAN 设备扫描" 12 宽, 不 pad 会让行间左列模块名右端参差)。
            # 用 ASCII 空格 pad: 跨终端/跨字体渲染稳定 (全角空格在
            # Windows Consolas 下仅 0.37 倍 ASCII 宽, 不能用作 pad)。
            #
            # 历史上 cell 末尾还跟了 " (key)" 一段, 后因 cmd + Consolas
            # 字体下汉字实际仅 1.629 倍 ASCII 宽 (非理论 2.0 倍), 加上
            # key 长度参差 (3-11 字符) 后 cell 实际像素宽差异过大, pad
            # 整数 ASCII 空格无法在 Consolas 下做到像素级行间对齐, 故
            # 移除 (key) 段以减小 cell 宽差异 (现仅 0.06 字符位, 肉眼看不出)。
            # 用户仍可通过序号 (1-19) 或分类字母 (a/b/c) 选模块, 不受影响。
            name_max_w = name_max_w_global
            for k in keys:
                idx += 1
                n = MODULE_MAP[k][0]
                name_padded = n + " " * (name_max_w - _disp_width(n))
                cells.append(
                    _c(str(idx).rjust(2), C_CYAN) + ". " +
                    _c(name_padded, C_WHITE))
            for line in _columnize(cells, columns=2, gap=4):
                print("    " + line)
        print()
        print(f"    {_c(' 0', C_CYAN)}. 运行全部诊断 {_c('(默认并发, 含Ookla官方测速)', C_GRAY)}")
        print(f"    {_c(' m', C_CYAN)}. 盯障模式 {_c('(600秒找偶发掉线, Ctrl+C可提前停)', C_GRAY)}")
        print(f"    {_c(' e', C_CYAN)}. 导出上次诊断报告")
        print(f"    {_c(' d', C_CYAN)}. 生成调试包 {_c('(脱敏zip: 报告+证据+日志, 上报排障用)', C_GRAY)}")
        print(f"    {_c(' r', C_CYAN)}. 返回场景模式主菜单")
        print(f"    {_c(' q', C_CYAN)}. 退出")
        print(_c("  快捷: 0=全部 a/b/c=按分类 m=盯障 e=导出 d=调试包 r=返回场景 q=退出", C_GRAY))
        print(_c("-" * 60, C_GRAY))
        try:
            choice = input(_c("  输入 > ", C_GREEN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice.lower() in ("q", "quit", "exit"):
            break
        # r / return: 返回场景层主菜单 (v1.9.3)。r 不与分类字母 (a/b/c)、
        # 模块 key 或命令 (m/e) 冲突; 置于 parse_choice 之前, 避免被当模块解析
        if choice.lower() in ("r", "return", "back", "返回", "回场景", "场景"):
            return True
        # m / monitor: 盯障模式 (独立运行模式, 不进模块注册表)
        # 默认 600 秒直接跑, 不再询问时长 (减少输入; Ctrl+C 可提前结束)
        if choice.lower() in ("m", "monitor", "盯障"):
            run_monitor_mode(600)
            try:
                input(_c("  按 Enter 返回菜单...", C_GRAY))
            except (EOFError, KeyboardInterrupt):
                break
            continue
        # e / export: 不跑诊断, 直接导出上次报告 (回车返回菜单后无需重新测试)
        if choice.lower() in ("e", "export", "导出"):
            if not LAST_RUN:
                print(_c("  尚无诊断数据，请先运行一次诊断。", C_YELLOW))
            else:
                prompt_export_report()
            try:
                input(_c("  按 Enter 返回菜单...", C_GRAY))
            except (EOFError, KeyboardInterrupt):
                break
            continue
        # d / debug: 生成脱敏调试包 (v1.9.6, --debug-bundle 的菜单入口)。
        # 上报排障主通道: 无诊断数据时提示先跑 (不像 CLI 那样自动跑全诊断 —
        # 菜单里 30-120 秒的意外等待比一次提示更伤)。
        if choice.lower() in ("d", "debug", "调试包"):
            if not LAST_RUN:
                print(_c("  尚无诊断数据，请先运行一次诊断 (0=全部 或选模块)。", C_YELLOW))
            else:
                print(_c("  → 打包: system.json + diagnostic.json + evidence.json"
                         " + netpulse.log (SSID/MAC/公网IP/主机名 已脱敏)", C_GRAY))
                _export_debug_bundle(_report_dir())
                print(_c("  → 请将 zip 文件发给后端/厂商支持, 无需手工截图。", C_GRAY))
            try:
                input(_c("  按 Enter 返回菜单...", C_GRAY))
            except (EOFError, KeyboardInterrupt):
                break
            continue
        keys = parse_choice(choice)
        if keys is None:
            print(_c("  无效选择, 请重新输入。", C_YELLOW))
            try:
                input(_c("  按 Enter 继续...", C_GRAY))
            except (EOFError, KeyboardInterrupt):
                break
            continue
        # 端口探测: 单选 port 时才询问目标; 选 0/全部时自动跳过 (避免打断全流程)
        # (用户偏好: 端口探测必须有显式目标, 全量诊断时没目标就跳过不测)
        is_all = (len(keys) == len(MODULE_REGISTRY))
        if "port" in keys and not PORT_PROBE_CONFIG.get("targets"):
            if is_all:
                # 全量诊断: 没目标就跳过端口探测, 不打断流程
                print(_c("  → 端口探测无目标, 自动跳过 (单独选 port 可指定目标)", C_GRAY))
                keys = [k for k in keys if k != "port"]
            elif sys.stdout.isatty():
                prompted = _prompt_for_port_targets()
                if prompted is None:
                    print(_c("  已取消端口探测, 其余模块继续。", C_YELLOW))
                    keys = [k for k in keys if k != "port"]
                    if not keys:
                        try:
                            input(_c("  按 Enter 返回菜单...", C_GRAY))
                        except (EOFError, KeyboardInterrupt):
                            break
                        continue
                else:
                    tgt, proto, cnt = prompted
                    PORT_PROBE_CONFIG["targets"] = tgt
                    PORT_PROBE_CONFIG["proto"] = proto
                    PORT_PROBE_CONFIG["count"] = cnt
            else:
                keys = [k for k in keys if k != "port"]
        # 网页体检: 单选时询问追加目标 (v1.9.6, --web-target 的菜单入口)。
        # 全量诊断默认 3 站照跑, 不打断流程; 已有目标 (CLI 传入/本会话答过) 不再问。
        if ("web" in keys and not WEB_CONFIG.get("targets")
                and not is_all and sys.stdout.isatty()):
            extra = _prompt_for_web_targets()
            if extra:
                WEB_CONFIG["targets"] = extra
        # 测速: 单选时询问换节点 (v1.9.6, --speedtest-node 的菜单入口)。
        # 一次会话只问一次 (_node_prompted 标记); 全量诊断直接默认节点。
        if ("speedtest" in keys and not is_all and sys.stdout.isatty()
                and not SPEEDTEST_CONFIG.get("_node_prompted")):
            SPEEDTEST_CONFIG["_node_prompted"] = True
            _node = _prompt_for_speedtest_node()
            if _node:
                # 写入口径与 CLI --speedtest-node 一致: 始终记 node, 数字 ID
                # 同时切 ookla_server_id (覆盖默认 3633)
                SPEEDTEST_CONFIG["node"] = _node
                if _node.isdigit():
                    SPEEDTEST_CONFIG["ookla_server_id"] = int(_node)
                    print(_c(f"  → Ookla 节点切换为 {_node}", C_GRAY))
                else:
                    print(_c(f"  → 测速上行节点: {_node}", C_GRAY))
        # iperf3 模块: 单选 iperf3 时才询问服务器; 选 0/全部时自动跳过
        # (iperf3 需要用户自备服务器, 全量诊断时没服务器就跳过不测)
        if ("iperf3" in keys and not SPEEDTEST_CONFIG.get("iperf3_server")):
            if is_all:
                print(_c("  → iperf3 无服务器, 自动跳过 (单独选 iperf3 可配置)", C_GRAY))
                keys = [k for k in keys if k != "iperf3"]
            elif sys.stdout.isatty():
                iperf3 = _prompt_for_iperf3()
                if iperf3 is not None:
                    host, port = iperf3
                    SPEEDTEST_CONFIG["iperf3_server"] = host
                    SPEEDTEST_CONFIG["iperf3_port"] = port
                    print(_c(f"  → iperf3 server: {host}:{port}", C_GRAY))
                    Iperf3Tester()._find_iperf3(auto_download=True)
                else:
                    print(_c("  → 未提供 iperf3 服务器, 该模块运行时会提示缺少服务器", C_GRAY))
            else:
                keys = [k for k in keys if k != "iperf3"]
        # iperf3 测速口径 (v1.9.6, --iperf3-udp 的菜单入口): 服务器已具备
        # (CLI 传入或刚答) 且单选时追问一次 TCP/UDP; 一次会话只问一次。
        if ("iperf3" in keys and not is_all and sys.stdout.isatty()
                and SPEEDTEST_CONFIG.get("iperf3_server")
                and not SPEEDTEST_CONFIG.get("_iperf3_mode_prompted")):
            SPEEDTEST_CONFIG["_iperf3_mode_prompted"] = True
            if _prompt_for_iperf3_mode() == "udp":
                SPEEDTEST_CONFIG["iperf3_udp"] = True
                print(_c("  → iperf3 改用 UDP 口径 (抖动/丢包, 1 Mbps 发包率)", C_GRAY))
        # 菜单模式: 多模块默认并发 (与 CLI `all --parallel` 对齐)。
        # run_diagnostics 内部 `parallel and len(keys) > 1` 会自动避免
        # 单模块走并发 (无意义且会浪费线程开销)。
        run_diagnostics(keys, banner=False, parallel=True, max_workers=4)
        if sys.stdout.isatty():
            # 单独跑测速时跳过"生成综合诊断报告"询问: 测速已自动保存独立的
            # 专业测速报告 (HTML+JSON), 再问会产生冗余的 netdiag_report_*
            if keys == ["speedtest"] or keys == ["iperf3"]:
                print(_c(f"  测速报告已自动保存至 reports/ 目录 ({keys[0]}_时间戳.html/.json)。",
                         C_GRAY))
            else:
                prompt_export_report()
        try:
            input(_c("\n  按 Enter 返回菜单...", C_GRAY))
        except (EOFError, KeyboardInterrupt):
            break
    # q / Ctrl+C / EOF → False (退出整个程序); r → True (返回场景层) 已在上面提前 return
    return False


def main():
    # v1.9.7 PR-2: scapy 后台预加载 — 越早开线程, 菜单渲染完时越可能已加载完
    _start_scapy_preload()
    parser = argparse.ArgumentParser(
        prog="netpulse.py",
        description=f"{APP_NAME} v{APP_VERSION} — Windows 网络诊断工具 (命令行)")
    parser.add_argument("modules", nargs="*",
                        help="要运行的模块 key 或序号 (默认进入交互菜单); 用 --list 查看")
    parser.add_argument("--list", action="store_true",
                        help="列出所有可用诊断模块后退出")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 格式输出每个模块的完整结果")
    parser.add_argument("--verbose", action="store_true",
                        help="完整输出, 不截断长字段")
    parser.add_argument("--no-color", action="store_true",
                        help="禁用彩色输出 (兼容老旧终端)")
    parser.add_argument("--diagnose", metavar="PROFILE",
                        choices=sorted(list(DIAGNOSE_PROFILES.keys())),
                        help="按场景 Profile 诊断 (阶段 C · v1.3.0 引入). "
                             "可选: slow / disconnect / web / gaming / wifi. "
                             "诊断完成后输出根因分析 (置信度 + 建议). "
                             "也支持子命令形式: netpulse diagnose <profile>. "
                             "例: netpulse.py --diagnose slow")
    parser.add_argument("--json-schema", action="store_true",
                        help="输出当前 JSON Schema 版本号与结构路径 (阶段 D · v1.4.0 引入). "
                             "供 AI Agent / RMM / 飞书 bot introspect 用, "
                             "无需跑诊断即可查询 schema_version 与字段定义文件位置.")
    parser.add_argument("--debug-bundle", metavar="DIR",
                        help="生成调试包 (阶段 D · v1.4.0 引入). "
                             "zip 含 system.json + diagnostic.json + evidence.json + netpulse.log, "
                             "默认脱敏 (SSID / MAC / 公网 IP / hostname). "
                             "用于上报 bug 或远端排障. 例: --debug-bundle ./out")
    parser.add_argument("--install", action="store_true",
                        help="自动安装缺失依赖 (scapy/Npcap), 无需交互确认")
    parser.add_argument("--install-npcap", action="store_true",
                        help="仅安装 Npcap 抓包驱动后进入菜单 (v1.9.7 PR-3; "
                             "自提权重启的落点 — 需管理员权限, 普通权限下仅提示)")
    parser.add_argument("--no-scapy", action="store_true",
                        help="禁用 scapy 二层抓包 (部分机器 Npcap 不稳定会崩溃), "
                             "DHCP 检测降级为仅读取当前 DHCP 服务器")
    parser.add_argument("--port-target", action="append", metavar="HOST:PORT",
                        help="端口探测目标, 格式 host:port (如 223.5.5.5:53) 或 "
                             "host:port1-port2 范围 (如 10.0.0.1:1-1024) 或 "
                             "host:port,port (如 8.8.8.8:80,443,8000-8100); "
                             "可多次指定或用逗号分隔, 例: --port-target 223.5.5.5:53,10.0.0.1:1-1024")
    parser.add_argument("--port-proto", choices=["tcp", "udp", "both"], default="tcp",
                        help="端口探测协议 (默认 tcp); both = TCP 与 UDP 均测")
    parser.add_argument("--port-count", type=int, default=2, metavar="N",
                        help="每个目标采样次数 (默认 2; 越大越可靠但越慢, 1=快速, 10=高可靠)")
    parser.add_argument("--port-force", action="store_true",
                        help="强制执行端口探测, 即使目标数超过 1000 上限 "
                             "(默认拦下, 避免无意探测风暴/DoS)")
    parser.add_argument("--port-timeout", type=float, default=60.0, metavar="SEC",
                        help="端口探测总时长上限 (秒, 默认 60, 设 0 = 不限)。"
                             "超过则跳过剩余 spec, 报告里 timed_out_specs 字段列出")
    parser.add_argument("--port-concurrency", type=int, default=8, metavar="N",
                        help="端口探测内部并发度 (默认 8, 1=串行, 上限 64)。"
                             "并发下 60s 内能扫 20-50 个端口, 串行只扫 4-5 个")
    parser.add_argument("--export", metavar="FILE",
                        help="诊断后将报告导出到文件 (支持 .html / .json); "
                             "多个目标用逗号分隔可一次导出多种格式, 例: report.html,report.json")
    parser.add_argument("--parallel", action="store_true",
                        help="多模块并发执行 (典型场景: `all` 时速度提升 2-3x; "
                             "输出经线程锁同步, 详细结果仍按 keys 顺序排列)")
    parser.add_argument("--max-workers", type=int, default=4, metavar="N",
                        help="并行模式下的最大并发数 (--parallel 时生效, 默认 4)")
    parser.add_argument("--pip-mirror", metavar="URL",
                        help="pip 镜像 URL, 显式覆盖自动选源。"
                             "例: --pip-mirror https://pypi.tuna.tsinghua.edu.cn/simple")
    parser.add_argument("--iperf3-server", metavar="HOST[:PORT]",
                        help="iperf3 服务器地址: 提供后 iperf3 模块测到该服务器的上下行吞吐"
                             "(iperf3.exe 缺失时会交互式询问自动下载)。这是独立模块, "
                             "与互联网宽带测速 (speedtest) 分开, 测的是链路吞吐而非宽带。"
                             "例: 192.168.1.10 或 192.168.1.10:5201")
    parser.add_argument("--iperf3-duration", type=int, default=10, metavar="SEC",
                        help="iperf3 单方向测速时长 (秒, 默认 10)")
    parser.add_argument("--iperf3-udp", action="store_true",
                        help="iperf3 改用 UDP 模式测抖动/丢包 (1 Mbps 发包率, 语音/游戏"
                             "质量口径): 抖动 >30ms 或丢包 >1%% 给出告警; 默认 TCP 测吞吐")
    parser.add_argument("--speedtest-net", action="store_true",
                        help="启用 Ookla Speedtest 官方测速 (CLI 默认关闭; "
                             "交互菜单默认启用, 上海电信节点 3633)。"
                             "用 --speedtest-node <ID> 可指定其他服务器")
    parser.add_argument("--speedtest-node", metavar="ID|HOST:PORT",
                        help="指定测速服务器 (可选): 数字 ID = Ookla 服务器 ID "
                             "(覆盖默认 3633 上海电信, 如 5396 北京联通); "
                             "host:port = 国内上行节点 (如 112.25.80.50:8080); "
                             "默认自动选择国内运营商节点")
    parser.add_argument("--nattype-server", action="append", metavar="HOST[:PORT]",
                        help="NAT 类型检测的 STUN 服务器 (可选, 可指定两次提供两台, "
                             "缺省端口 3478); 默认用内置国内服务器自动回退")
    parser.add_argument("--web-target", action="append", metavar="URL",
                        help="网页体检追加目标 (可选, 追加到默认 3 个国内大站后, "
                             "总数上限 8), 例: --web-target https://example.com")
    parser.add_argument("--tcpcc-target", metavar="HOST:PORT",
                        help="TCP 并发测试的自定义目标 (可选, 如自建服务器/内网设备); "
                             "默认自动挑公网 anycast DNS 的 TCP 53 端点")
    parser.add_argument("--tcpcc-max", type=int, default=1600, metavar="N",
                        help="TCP 并发阶梯上限 (默认 1600, 硬上限 8000)。高上限会短时"
                             "建立大量连接, 勿短时间重复运行; 并行模式下建议单跑本模块")
    parser.add_argument("--monitor", metavar="SEC", type=int, nargs="?", const=600,
                        help="盯障模式: 持续监测 SEC 秒找偶发掉线, 结束生成 CSV/HTML/JSON "
                             "报告 (不带值 = 600 秒; 范围 30-86400; Ctrl+C 提前结束同样"
                             "生成报告); 与其他模块互斥, 指定时忽略 modules 与 --export")
    parser.add_argument("--monitor-target", metavar="HOST",
                        help="盯障外网 ping 目标 (默认 223.5.5.5, 同时对该目标 TCP 53 "
                             "建连; 可用域名)")
    parser.add_argument("--monitor-load", action="store_true",
                        help="盯障期间生成 15s 主动下载负载 (制造 full-size 包让 TCP "
                             "重传统计有分母; 流式读即丢弃, 不落盘)")
    parser.add_argument("--load-url", metavar="URL",
                        help="主动负载的下载地址 (默认微信安装包 CDN 大文件, "
                             "配合 --monitor-load 使用)")
    parser.add_argument("--capture", nargs="?", const="slice",
                        choices=["slice", "full"], default=None, metavar="MODE",
                        help="盯障期间抓包取证 (需 Npcap + 管理员; 默认关闭): "
                             "slice=事件触发落盘前后 30s 切片, full=全程落一个 "
                             "pcap。仅保留包头 + 80/443 每流首 2 包 384B (提 "
                             "Host/SNI), 不存应用内容; 配合 --monitor 使用")
    parser.add_argument("--capture-mb", type=int, default=CAPTURE_DEFAULT_MB,
                        metavar="N",
                        help=f"抓包缓冲上限 MB (默认 {CAPTURE_DEFAULT_MB}, 最小 8); "
                             "超限挤掉最旧包并如实报告; 配合 --capture 使用")
    args = parser.parse_args()

    # `netpulse diagnose <profile>` 子命令形式 (与 README/CHANGELOG 文档口径
    # 一致): 等价转写为 --diagnose <profile>, 剩余 token 仍按模块名处理
    if args.modules and args.modules[0] == "diagnose":
        profiles = "/".join(sorted(DIAGNOSE_PROFILES.keys()))
        if args.diagnose:
            print(_c("  错误: 'diagnose' 子命令与 --diagnose 不能同时使用", C_RED))
            sys.exit(4)
        if len(args.modules) < 2:
            print(_c(f"  用法: netpulse diagnose <profile>  (可选: {profiles})", C_RED))
            sys.exit(4)
        profile = args.modules[1]
        if profile not in DIAGNOSE_PROFILES:
            print(_c(f"  错误: 未知 profile '{profile}'  (可选: {profiles})", C_RED))
            sys.exit(4)
        args.diagnose = profile
        args.modules = args.modules[2:]

    # 禁用 scapy 二层抓包 (避免 Npcap 不稳定导致段错误)
    if args.no_scapy:
        global FORCE_NO_SCAPY, SCAPY_AVAILABLE
        FORCE_NO_SCAPY = True
        SCAPY_AVAILABLE = False

    # 端口探测参数 -> 全局配置 (run_diagnostics 读取)
    # 注意: args.port_target 已经是 argparse action="append" 后的 list,
    # 每个元素是一个完整 spec (允许内部用逗号分隔多端口 / 用 - 范围)。
    # 多 host 必须用多个 --port-target, 例: --port-target a:80 --port-target b:80
    if args.port_target:
        targets = [p.strip() for p in args.port_target if p and p.strip()]
        PORT_PROBE_CONFIG["targets"] = targets or []
    PORT_PROBE_CONFIG["proto"] = args.port_proto
    PORT_PROBE_CONFIG["count"] = max(1, int(args.port_count))
    PORT_PROBE_CONFIG["force"] = bool(getattr(args, "port_force", False))
    PORT_PROBE_CONFIG["max_total_time"] = max(0.0, float(getattr(args, "port_timeout", 60.0)))
    PORT_PROBE_CONFIG["max_concurrency"] = max(1, min(64, int(getattr(args, "port_concurrency", 8))))

    # 测速参数 -> 全局配置 (runner -> SpeedTester.detect 读取)
    if args.iperf3_server:
        spec = args.iperf3_server.strip()
        if ":" in spec:
            host, _, port = spec.rpartition(":")
            if host and port.isdigit():
                SPEEDTEST_CONFIG["iperf3_server"] = host
                SPEEDTEST_CONFIG["iperf3_port"] = int(port)
            else:
                SPEEDTEST_CONFIG["iperf3_server"] = spec
        else:
            SPEEDTEST_CONFIG["iperf3_server"] = spec
    SPEEDTEST_CONFIG["use_speedtest_net"] = bool(args.speedtest_net)
    SPEEDTEST_CONFIG["node"] = getattr(args, "speedtest_node", None) or None
    # --speedtest-node 传数字 ID 时, 同时设为 Ookla 服务器 ID (覆盖默认 3633)
    sn = getattr(args, "speedtest_node", None)
    if sn and str(sn).strip().isdigit():
        SPEEDTEST_CONFIG["ookla_server_id"] = int(str(sn).strip())
    SPEEDTEST_CONFIG["iperf3_duration"] = max(1, int(getattr(args, "iperf3_duration", 10)))
    SPEEDTEST_CONFIG["iperf3_udp"] = bool(getattr(args, "iperf3_udp", False))

    # NAT 类型参数 -> 全局配置 (runner -> NATTypeTester.detect 读取)
    NATTYPE_CONFIG["servers"] = [s.strip() for s in (args.nattype_server or [])
                                 if s and s.strip()]

    # 网页体检参数 -> 全局配置 (runner -> WebPageTester.detect 读取)
    WEB_CONFIG["targets"] = [u.strip() for u in (args.web_target or [])
                             if u and u.strip()]

    # TCP 并发参数 -> 全局配置 (runner -> TCPConcurrencyTester.detect 读取)
    TCPCC_CONFIG["max"] = max(50, min(8000, int(getattr(args, "tcpcc_max", 1600) or 1600)))
    TCPCC_CONFIG["target"] = (getattr(args, "tcpcc_target", None) or "").strip() or None

    if args.list:
        _print_module_list()
        return
    # 阶段 D · v1.4.0: --json-schema 输出当前 JSON Schema 版本号 (无需跑诊断)
    if args.json_schema:
        schema_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "schema")
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "schema_dir": schema_dir if os.path.isdir(schema_dir)
                          else f"(未生成 — 见 schema/{SCHEMA_FILENAME})",
            "app": APP_NAME,
            "version": APP_VERSION,
        }, ensure_ascii=False, indent=2))
        return
    # 阶段 D · v1.4.0: --debug-bundle 生成调试包 (脱敏的诊断快照)
    if args.debug_bundle:
        _export_debug_bundle(args.debug_bundle)
        return
    # v1.9.7 PR-3: --install-npcap 自提权重启的落点 — 装完不退出,
    # 直接进菜单 (提权窗口保持可用, 用户接着做需要管理员的事)
    if args.install_npcap:
        _run_install_npcap_entry()
        # 不 return: 继续走到底部的交互菜单
    # 按场景 Profile 诊断 (阶段 C · v1.3.0 引入): 跑 profile 模块后追加根因分析
    if args.diagnose:
        profile = args.diagnose
        keys = DIAGNOSE_PROFILES[profile]
        print(_c(f"  按场景诊断: {profile} "
                 f"(模块: {', '.join(keys)})", C_BOLD))
        run_diagnostics(keys, verbose=args.verbose, as_json=args.json,
                        no_color=args.no_color, install=args.install,
                        parallel=args.parallel, max_workers=args.max_workers,
                        pip_mirror=args.pip_mirror)
        # 根因分析 (基于 run_diagnostics 写入的 LAST_RUN["results"])
        # v1.6.0 (PR-B): 按场景规则集评估, 避免 gaming 报 wifi 弱等无关根因
        if LAST_RUN and LAST_RUN.get("results"):
            diagnosis = diagnose(LAST_RUN["results"], rule_filter=profile)
            print(_c("─" * 60, C_BLUE))
            _print_diagnosis(diagnosis)
        # 与 modules 路径同权: --export / --json-schema 等后续动作不再被吞
        # v1.6.1: 导出与屏幕同一规则集, 报告不再夹带过滤掉的根因
        if args.export:
            _export_reports(args.export, rule_filter=profile)
        _exit_with_status()
        return
    # 盯障模式: 独立顶层运行模式 (与模块诊断互斥)
    if args.capture and not args.monitor:
        print(_c("  提示: --capture 仅在 --monitor 盯障模式下生效, 本次已忽略", C_YELLOW))
    if args.monitor:
        # v1.7.0 (PR-F0): 主动负载 opt-in — --monitor-load 用默认 CDN 大文件,
        # --load-url 可覆盖地址; 两者都没给则不制造流量
        if args.monitor_load or args.load_url:
            load_url = args.load_url or MonitorSession.MONITOR_LOAD_URL
        else:
            load_url = None
        run_monitor_mode(args.monitor, ext_target=args.monitor_target,
                         load_url=load_url, capture_mode=args.capture,
                         capture_mb=args.capture_mb)
        return
    if args.modules:
        is_all_only = (args.modules == ["all"])
        if is_all_only:
            keys = all_module_keys()
            if not args.json:      # JSON 输出不掺人读文本
                print(_c(_stress_excluded_hint(), C_GRAY))
        else:
            keys = parse_module_names(args.modules)
        if not keys:
            print("可用模块: " + ", ".join(k for k, _, _ in MODULE_REGISTRY))
            sys.exit(4)  # D2: 参数错 (模块名无效)
        # 端口探测: 不管是 all 还是单选 port, 跑之前都要求用户输入目标
        # (用户偏好: 端口探测必须有显式目标, 不再有隐式默认)
        if "port" in keys and not PORT_PROBE_CONFIG.get("targets"):
            if sys.stdout.isatty():
                prompted = _prompt_for_port_targets()
                if prompted is None:
                    print(_c("  已取消端口探测。", C_YELLOW))
                    return
                tgt, proto, cnt = prompted
                PORT_PROBE_CONFIG["targets"] = tgt
                PORT_PROBE_CONFIG["proto"] = proto
                PORT_PROBE_CONFIG["count"] = cnt
            else:
                print(_c("  错误: 端口探测必须指定目标。", C_RED))
                print(_c("  用法: netpulse.py port --port-target HOST:PORT [...]", C_GRAY))
                print(_c("  例:   netpulse.py port --port-target 192.168.1.1:443,8.8.8.8:53", C_GRAY))
                print(_c("       或: netpulse.py all --port-target 8.8.8.8:53", C_GRAY))
                sys.exit(4)  # D2: 参数错 (缺少 --port-target)
        run_diagnostics(keys, verbose=args.verbose, as_json=args.json,
                        no_color=args.no_color, install=args.install,
                        parallel=args.parallel, max_workers=args.max_workers,
                        pip_mirror=args.pip_mirror)
        if args.export:
            _export_reports(args.export)
        _exit_with_status()
        return
    # 无参数 -> 进入交互式菜单
    interactive_menu(install=args.install, pip_mirror=args.pip_mirror)


if __name__ == "__main__":
    main()
