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
from datetime import datetime
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.parse import urlsplit, urlunsplit, urljoin
import http.client
import ssl
import asyncio
import webbrowser

# 可选依赖 — 缺失时自动降级
try:
    from scapy.all import (
        Ether, IP, UDP, DHCP, BOOTP, ICMP, ARP,
        srp, sendp, sniff, conf, sr1, get_if_list, get_if_addr, get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# 强制禁用 scapy 二层抓包 (某些机器 Npcap 不稳定会段错误): 置 True 后 DHCP 走 ipconfig 降级
FORCE_NO_SCAPY = False

try:
    import speedtest
    SPEEDTEST_LIB_AVAILABLE = True
except Exception:
    SPEEDTEST_LIB_AVAILABLE = False

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

# 端口探测模块的运行参数 (由 CLI --port-* 写入, run_diagnostics 读取)
PORT_PROBE_CONFIG = {"targets": [], "proto": "tcp", "count": 2,
                     "force": False, "max_total_time": 60.0,
                     "max_concurrency": 8}

# 测速 / iperf3 模块的运行参数 (由 CLI 写入, runner 读取)
# - iperf3_server / iperf3_port / iperf3_duration: iperf3 独立模块用, 由 --iperf3-server 提供;
#   提供后 iperf3 模块测到该服务器的上下行吞吐 (iperf3 是最准的链路吞吐测量)
# - use_speedtest_net: 默认关闭 — 国内网络下 speedtest-cli 常选中海外服务器,
#   结果严重偏低 (本机实测 100M 宽带测出 5 Mbps), 仅作参考
# - node: 手动指定上行测速服务器 (speedtest 服务器 ID 或 host:port); 默认自动选国内运营商节点
# - duration_down / duration_up: 上下行测速时长 (秒)
# - live_ui: 单独运行测速模块时启用终端实时可视化 (由 run_diagnostics 写入)
SPEEDTEST_CONFIG = {"iperf3_server": None, "iperf3_port": 5201, "iperf3_duration": 10,
                    "use_speedtest_net": False,
                    "node": None, "duration_down": 8.0, "duration_up": 8.0,
                    "live_ui": False}

# NAT 类型模块的运行参数 (由 CLI --nattype-server 写入, runner 读取)
# 为空时用内置候选 (实测可用的排前), 给 1~2 台则覆盖
NATTYPE_CONFIG = {"servers": []}

# 网页体检模块的运行参数 (由 CLI --web-target 写入, 追加到默认 3 目标后)
WEB_CONFIG = {"targets": []}

# TCP 并发模块的运行参数 (由 CLI --tcpcc-max / --tcpcc-target 写入)
# - max: 阶梯上限 (默认 1600, 硬上限 8000; Windows 临时端口 ~16k, 高上限勿短时重复跑)
# - target: 自定义目标 host:port (默认自动挑公网 anycast DNS 的 TCP 53)
TCPCC_CONFIG = {"max": 1600, "target": None}


def _is_admin():
    """检测当前是否以管理员权限运行 (安装 Npcap 需要)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


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
# PIP 镜像自动选源
# ============================================================
#
# 国内网络环境下, pypi.org 经常卡到超时 (TCP RST / 极慢 / 间歇性失败),
# 装 scapy / reportlab 等依赖会卡 5-10 分钟。自动探测并切到国内镜像:
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
    """下载并以静默方式安装 Npcap (需管理员权限)。返回 (ok, msg)。"""
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


def _reload_scapy():
    """运行时重新导入 scapy 并绑定到模块命名空间。返回是否成功。"""
    global SCAPY_AVAILABLE, Ether, IP, UDP, DHCP, BOOTP, ICMP, ARP
    global srp, sendp, sniff, conf, sr1, get_if_list, get_if_addr, get_if_hwaddr
    try:
        from scapy.all import (
            Ether, IP, UDP, DHCP, BOOTP, ICMP, ARP,
            srp, sendp, sniff, conf, sr1, get_if_list, get_if_addr, get_if_hwaddr
        )
        SCAPY_AVAILABLE = True
        return True
    except Exception:
        SCAPY_AVAILABLE = False
        return False


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

    return SCAPY_AVAILABLE


# ============================================================
# SECTION 2: CONSTANTS
# ============================================================

APP_NAME = "NetPulse"
APP_VERSION = "1.0.0"


# 常用外网测试目标 (国内网络环境)
# 格式: (host, name, tcp_port)
#   tcp_port 用于 TCP 可达性预检 (应对 ICMP 被防火墙过滤的场景:
#   很多企业网禁 ping 到 8.8.8.8 / 114.114.114.114 等公共 DNS 或国际
#   站点, 但这些目标的 TCP 服务端口通常是开的, 不应该判为不可达)
EXTERNAL_TARGETS = [
    ("223.5.5.5", "AliDNS", 53),
    ("114.114.114.114", "114DNS", 53),
    ("119.29.29.29", "DNSPod", 53),
    ("www.baidu.com", "Baidu", 80),
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
              "min_ms": 0, "avg_ms": 0, "max_ms": 0, "rtts": [], "jitter_ms": 0}
    # 解析回复行 - 匹配 "时间=2ms" / "time=2ms" / "时间<1ms" / "time<1ms"
    for line in output.split("\n"):
        # 先检查 <1ms 模式
        if re.search(r"(?:[Tt]ime|时间)<\s*1?\s*ms", line):
            result["rtts"].append(0)
        else:
            m = re.search(r"(?:[Tt]ime|时间)[=<]\s*(\d+)\s*ms", line)
            if m:
                result["rtts"].append(int(m.group(1)))
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


def ping_host(host, count=20, packet_size=64, timeout=30):
    """Ping 指定主机"""
    cmd = f"ping -n {count} -l {packet_size} -w {timeout*1000//count} {host}"
    code, out, _ = run_cmd(cmd, timeout=timeout + 10)
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


class GatewayTester:
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

        ping_result = ping_host(gateway, count=count, timeout=count + 10)

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
            "summary": f"网关 {gateway}: 平均 {ping_result['avg_ms']}ms, "
                       f"丢包 {ping_result['loss_pct']}%, 抖动 {ping_result['jitter_ms']}ms",
        }
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

        # 2. TTL 分析 — 检测异常 TTL
        if callback:
            callback("TTL 分析...")
        if gateway:
            ping_result = ping_host(gateway, count=10, timeout=15)
            # 正常内网网关 TTL 通常为 64 (Linux) 或 128 (Windows)
            # 如果 TTL 远低于预期，可能存在环路
            code, ping_out, _ = run_cmd(f"ping -n 1 {gateway}")
            ttl_match = re.search(r"TTL=(\d+)|TTL=\s*(\d+)", ping_out, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1) or ttl_match.group(2))
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

        # 3. 检查重复 ARP 响应
        if gateway and gateway in ip_to_mac:
            gw_mac = ip_to_mac[gateway]
            # 检查是否有其他 IP 使用相同 MAC 作为网关
            same_mac_ips = [ip for ip in mac_to_ips.get(gw_mac, []) if ip != gateway]
            if same_mac_ips:
                issues.append({
                    "type": "gateway_mac_shared",
                    "severity": "info",
                    "message": f"网关 MAC {gw_mac} 也被以下 IP 使用: {', '.join(same_mac_ips[:3])}",
                    "detail": "可能是同一设备有多个接口，也可能需要进一步排查"
                })

        # 4. 检查网关丢包模式 (环路常导致间歇性丢包)
        if gateway:
            ping_result = ping_host(gateway, count=15, timeout=20)
            if ping_result["loss_pct"] > 0 and ping_result["loss_pct"] < 50:
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

        # 平均延迟只在 ping 通的目标上算 (禁拼目标不参与)
        ping_rtts = [r["ping_avg_ms"] for r in results
                    if r["ping_avg_ms"] > 0]
        avg_rtt = sum(ping_rtts) / len(ping_rtts) if ping_rtts else 0

        # 平均丢包只在 ping 通的目标上算 (禁拼目标不参与, 避免 100% 拖累)
        ping_losses = [r["ping_loss_pct"] for r in results
                      if r["reachability"] in ("ok", "tcp_blocked")]
        avg_loss = sum(ping_losses) / len(ping_losses) if ping_losses else 100

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

        # 评估: TCP 可达性优先
        if tcp_ok_count == len(results) and avg_loss == 0 and avg_rtt < 50:
            assessment = "外网连通正常"
        elif tcp_ok_count == len(results) and avg_loss < 5:
            assessment = "外网连通性良好"
        elif tcp_ok_count == len(results):
            assessment = "外网存在一定丢包"
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
        if avg_loss >= 5:
            issues.append({
                "type": "external_high_loss", "severity": "critical",
                "message": f"外网平均丢包 {avg_loss:.1f}%",
                "detail": "明显丢包: 网页卡顿、游戏掉线、视频花屏",
                "action": "网关正常而此处丢包 → 问题在运营商侧, 保留报告 (含逐跳路径) 带回报障",
            })
        elif avg_loss >= 1:
            issues.append({
                "type": "external_loss", "severity": "warning",
                "message": f"外网平均丢包 {avg_loss:.1f}%",
                "detail": "轻度丢包会影响游戏/通话体验",
                "action": "结合网关模块丢包判断段位: 网关也丢=内网问题; 网关不丢=外线问题",
            })
        if avg_rtt >= 150:
            issues.append({
                "type": "external_high_rtt", "severity": "warning",
                "message": f"外网平均延迟 {avg_rtt:.0f}ms",
                "detail": "延迟偏高, 游戏类应用会明显感觉慢",
                "action": "看路径追踪逐跳延迟, 从哪一跳开始升高, 问题就在那一段",
            })

        # 拼接 summary 包含禁拼提示
        summary_parts = [f"外网检测: 平均延迟 {avg_rtt:.0f}ms, 平均丢包 {avg_loss:.1f}%"]
        if unreachable_count > 0:
            summary_parts.append(f"{unreachable_count} 个不可达")
        if blocked_count > 0:
            summary_parts.append(f"{blocked_count} 个禁拼")
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


class WiFiAnalyzer:
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

    def test_speedtest(self, callback=None):
        """speedtest-cli 测速 (可选, 默认关闭; 国内网络下结果仅作参考)。

        国内现状: speedtest-cli 的服务器选点常指向海外服务器 (本机实测选中
        美国亚利桑那州服务器, 100M 宽带测出 5 Mbps, 而国内镜像实测 64.6
        Mbps)。因此:
          - 只在 use_speedtest_net=True 时运行 (默认不跑, 避免输出误导数字)
          - 选中服务器非中国大陆/港澳台时, 结果标记 valid=False 并附 note
        """
        if callback:
            callback("Speedtest.net 测速中 (可选, 结果仅供参考)...")
        if not SPEEDTEST_LIB_AVAILABLE:
            return {"error": "speedtest 库未安装", "method": "speedtest_lib"}

        try:
            st = speedtest.Speedtest(secure=True)
            if callback:
                callback("选择最优服务器...")
            st.get_best_server()
            server = st.best
            country = str(server.get("country", "") or "")
            cc = str(server.get("cc", "") or "").upper()
            # 中国大陆 + 港澳台视为"国内可达", 其它 (海外) 标记结果无效
            valid = (cc in ("CN", "HK", "MO", "TW")
                     or "中国" in country or "Hong Kong" in country
                     or "Macao" in country or "Macau" in country
                     or "Taiwan" in country)
            if callback:
                callback("下载测速中...")
            download_speed = st.download() / 1e6  # Mbps
            if callback:
                callback("上传测速中...")
            upload_speed = st.upload() / 1e6
            result = {
                "method": "speedtest.net",
                "server": f"{server.get('sponsor', '')} ({server.get('name', '')}, {country})",
                "server_country": country,
                "server_cc": cc,
                "server_latency_ms": round(server.get('latency', 0), 1),
                "download_mbps": round(download_speed, 2),
                "upload_mbps": round(upload_speed, 2),
                "valid": valid,
            }
            if not valid:
                result["note"] = (f"Speedtest.net 选中服务器位于海外 ({country}), "
                                  "跨境链路测速结果不代表本地宽带速率, 仅供参考")
            return result
        except Exception as e:
            return {"error": str(e), "method": "speedtest_lib"}

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
                    return {"error": f"无法解析测速节点: {node} (支持 host:port, "
                                     "如 112.25.80.50:8080)", "method": "upload_cn"}
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
        """解析 --speedtest-node: host:port → 手工构造 server dict; 数字 ID 不支持。"""
        node = str(node).strip()
        host, _, port = node.rpartition(":")
        if not host or not port.isdigit():
            return None
        return {"host": f"{host}:{port}", "sponsor": node, "cc": "CN",
                "country": "手动指定"}

    def detect(self, use_speedtest_net=False, node=None, live_ui=False,
               save_report=True, callback=None):
        """完整测速 (带宽体检) — 纯互联网宽带测速, 不含 iperf3 (iperf3 已是独立模块)。

        流程: ① 空闲延迟基线 → ② 下行测速 (国内镜像多连接, 并行采样负载延迟)
        → ③ 上行测速 (国内运营商节点) → ④ 汇总评级
        (下行/上行/预估带宽/bufferbloat A-F) → ⑤ 本地 HTML+JSON 报告。

        live_ui: 单独运行本模块时终端实时动画 (由 run_diagnostics 置位)。
        save_report: 结束后保存独立测速报告到 reports/YYYY-MM-DD/。
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

        # Speedtest.net 参考 (可选)
        speedtest_result = None
        if use_speedtest_net:
            speedtest_result = self.test_speedtest(_cb)

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
    download = res.get("download_mbps") or 0
    upload = res.get("upload_mbps")
    est = res.get("estimated_bandwidth") or {}
    grade = str(res.get("bufferbloat_grade") or "—")
    # 把 "A (优秀, 无缓冲膨胀)" 拆成简短字母 + 评语 (与主报告 metric 卡策略一致,
    # 避免卡片被长字符串撑大)
    g0 = grade.split(" ", 1)[0] if grade and grade != "—" else "—"
    g_rest = grade[len(g0):].strip(" ()") if g0 != "—" else ""
    grade_letter = g0
    grade_note = g_rest or ""
    idle_rtt = res.get("idle_rtt_ms")
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
    upload_server = res.get("upload_server") or "未测"
    upload_method = res.get("upload_method") or "未测"
    idle_str = f"{idle_rtt:.0f} ms" if idle_rtt is not None else "—"
    loaded_str = f"{loaded_rtt:.0f} ms" if loaded_rtt is not None else "—"
    bloat_str = f"{bloat_ms:+.0f} ms" if bloat_ms is not None else "—"
    # 测速源信息: 下行 (国内镜像多连接) / 上行 (国内运营商节点)
    src_url = (res.get("http") or {}).get("url", "")
    src_domain = src_url.split("/")[2] if src_url.startswith("http") else "国内镜像"
    down_threads = (res.get("http") or {}).get("threads", 4)
    up_threads = (res.get("up_result") or {}).get("threads", 4)
    down_note = f"{down_threads} 连接 × {src_domain}"
    # 大数字指标 (主流测速报告风格: 下行/上行/延迟)
    up_big = f"{upload:.1f}" if upload is not None else "未测"
    ping_big = f"{idle_rtt:.0f}" if idle_rtt is not None else "—"
    # 测速节点延迟 (TCP 握手, 与报告"延迟 Ping"的 ICMP 网关延迟区分)
    up_res = res.get("up_result") or {}
    server_lat = up_res.get("server_latency_ms")
    server_lat_str = (f"{server_lat:.0f} ms (TCP 握手)" if server_lat is not None else "—")

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
  <div class="sub">客观速率/延迟实测数据, 不含达标判定</div>

  <div class="metric-row">
    <div class="metric down">
      <div class="label">下载</div>
      <div class="big">{download:.1f}<span class="unit"> Mbps</span></div>
      <div class="note">{down_note}</div>
    </div>
    <div class="metric up">
      <div class="label">上传</div>
      <div class="big">{up_big}<span class="unit"> Mbps</span></div>
      <div class="note">{upload_server} · {up_threads} 连接</div>
    </div>
    <div class="metric ping">
      <div class="label">延迟 (网关)</div>
      <div class="big">{ping_big}<span class="unit"> ms</span></div>
      <div class="note">空闲基线 · 下行/上行负载下还会测一次算缓冲膨胀</div>
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
      <tr><td>下行测速方式</td><td>国内镜像多连接 HTTP 下载 ({down_threads} 连接 × {src_domain})</td></tr>
      <tr><td>上行测速方式</td><td>{upload_method} ({upload_server}) · {up_threads} 连接</td></tr>
      <tr><td>延迟采样目标</td><td>{res.get("latency_target", "—")} (空闲/负载延迟均对它测)</td></tr>
      <tr><td>测速节点延迟</td><td>{server_lat_str}</td></tr>
      <tr><td>延迟采样阶段</td><td>空闲基线 → 下行 → 上行 (全程并行采样)</td></tr>
    </table>
  </div>

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

    返回页眉 HTML 字符串。
    """
    g1, g2, g3 = gradient
    return f"""<header class="brand-banner">
  <span class="logo"></span>
  <div class="brand-text">
    <div class="brand-row"><span class="brand-name">NetPulse</span><span class="brand-ver">v1.0.0</span></div>
    <h1>{title}</h1>
    <div class="brand-sub">{sub_text}</div>
  </div>
</header>
<style>
.brand-banner{{background:linear-gradient(135deg,{g1} 0%,{g2} 55%,{g3} 100%);
  color:#fff;padding:24px 28px;display:flex;align-items:center;gap:16px;
  border-radius:14px;box-shadow:0 8px 24px -10px rgba(11,31,58,.45);margin-bottom:24px;
  position:relative;overflow:hidden}}
.brand-banner::before{{content:'';position:absolute;top:-40%;right:-15%;width:340px;height:340px;
  background:radial-gradient(circle,rgba(96,165,250,.18) 0%,transparent 70%);pointer-events:none}}
.brand-banner .logo{{width:36px;height:36px;border-radius:9px;
  background:linear-gradient(135deg,#7ab3f5,#3b82f6);position:relative;flex:none}}
.brand-banner .logo::after{{content:'';position:absolute;inset:8px;
  border:2px solid rgba(255,255,255,.92);border-radius:3px}}
.brand-text{{flex:1;min-width:0}}
.brand-row{{display:flex;align-items:center;gap:8px;margin-bottom:2px}}
.brand-name{{font-size:14px;font-weight:700;color:#dbeafe;letter-spacing:.3px}}
.brand-ver{{font-size:11px;font-weight:600;color:#bfdbfe;
  background:rgba(255,255,255,.14);padding:1px 9px;border-radius:999px}}
.brand-banner h1{{font-size:22px;font-weight:800;letter-spacing:.5px;margin:4px 0 2px;color:#fff}}
.brand-sub{{font-size:12.5px;color:#9db8dd}}
</style>"""


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
            ping_result = ping_host(gw, count=10, timeout=15)
            status = ("正常" if ping_result["loss_pct"] == 0 else
                      f"丢包 {ping_result['loss_pct']}%"
                      if ping_result["loss_pct"] < 50 else "故障")
            return {
                "gateway": gw,
                "interface": route["interface"],
                "metric": route["metric"],
                "ping_loss_pct": ping_result["loss_pct"],
                "ping_avg_ms": ping_result["avg_ms"],
                "status": status,
                "_critical": ping_result["loss_pct"] >= 50,
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

class DNSTester:
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

        def _measure_mtu(target):
            """二分查找 MTU (ICMP payload: MTU - 28)。

            与原实现的区别:
            - 区分「无信号」(超时/丢包) 与「太大」(DF 拒绝) 两种情形;
              原实现把超时一律当「太大」, 在 ICMP 被防火墙过滤的环境下
              会返回错误的 path_mtu (实际上是探测失败, 但被报告为正常)。
            - 多次无信号直接放弃, 返回 error 而非假数据。
            - 加入总探测次数上限, 防止边界死循环。
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

        if callback:
            callback(f"MTU 检测 {len(targets)} 个目标 (并发)...")
        results = []
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as ex:
            for r in ex.map(_measure_mtu, targets):
                results.append(r)

        # 本地接口 MTU
        code, out, _ = run_ps(
            "Get-NetIPInterface -AddressFamily IPv4 | "
            "Where-Object {$_.ConnectionState -eq 'Connected'} | "
            "Select-Object InterfaceAlias, NlMtu | ConvertTo-Json"
        )
        local_mtus = []
        if out and out.strip():
            try:
                data = json.loads(out)
                if not isinstance(data, list):
                    data = [data]
                for item in data:
                    local_mtus.append({
                        "interface": item.get("InterfaceAlias", ""),
                        "mtu": item.get("NlMtu", 0),
                    })
            except Exception:
                pass

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


class ARPAnalyzer:
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


class RouteTableAnalyzer:
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

    用法: 交互菜单选 port, 或 CLI `port` 不带 --port-target 时调用。
    非 TTY 场景不应调用本函数 (调用方需先 sys.stdout.isatty() 判断)。
    """
    print(_c("  端口探测必须指定目标 (host:port), 不再内置默认值。", C_YELLOW))
    print(_c("  格式: HOST:PORT (例: 192.168.1.1:443)", C_GRAY))
    print(_c("  范围: HOST:port1-port2 (例: 10.0.0.1:1-1024) 或混合 HOST:80,443,8000-8100", C_GRAY))
    print(_c("  协议: tcp / udp / both (默认 tcp)。采样次数默认 4。", C_GRAY))
    print(_c("  上限: 单次探测目标数不超过 1000 (防探测风暴), 强制请用 --port-force", C_GRAY))
    try:
        spec = input(_c("  目标 > ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not spec:
        return None
    # 解析目标列表 (逗号分隔, 空白容错)
    parts = [p.strip() for p in spec.replace("，", ",").split(",") if p.strip()]
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
        print(_c(f"  → 共展开 {expanded_count} 个探测目标 (含端口范围)", C_GRAY))
    # 协议
    try:
        proto = input(_c("  协议 [tcp/udp/both] (默认 tcp) > ", C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        proto = "tcp"
    if proto not in ("tcp", "udp", "both"):
        proto = "tcp"
    # 采样次数
    try:
        cnt_raw = input(_c("  采样次数 (默认 4) > ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        cnt_raw = ""
    try:
        cnt = max(1, int(cnt_raw)) if cnt_raw else 4
    except ValueError:
        cnt = 4
    return valid, proto, cnt


def _prompt_for_iperf3():
    """交互式询问 iperf3 服务器地址。返回 (host, port) 或 None。

    iperf3 是独立模块: 测到指定服务器的链路吞吐 (非互联网宽带), 需要部署
    iperf3 服务器 (通常在出口网关/IDC/内网)。不提供服务器则模块明确报缺服务器,
    不会回退成宽带测速 (两者已彻底分离)。

    用法: 交互菜单选 iperf3 模块, 且 CLI 未传 --iperf3-server 时调用。
    非 TTY 场景不应调用 (调用方需先 sys.stdout.isatty() 判断)。
    """
    print(_c("  iperf3 链路吞吐测试: 需 iperf3 服务器 (通常部署在出口/IDC)", C_YELLOW))
    print(_c("  提示: 没 iperf3 服务器直接回车, 该模块将提示缺少服务器", C_GRAY))
    try:
        ans = input(_c("  是否配置 iperf3 服务器? [y/N] > ", C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if ans not in ('y', 'yes'):
        return None
    # 询问 server 地址
    try:
        spec = input(_c("  iperf3 server (HOST 或 HOST:PORT, 缺省 :5201) > ", C_GREEN)).strip()
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


class TCPStatsTester:
    """TCP 传输质量统计 (重传率/错误段/失败连接), 基于 Get-NetTCPStatistics。"""

    def __init__(self):
        self.name = "TCP 传输质量"
        self.results = {}

    def detect(self, callback=None):
        if callback:
            callback("采集 TCP 传输统计...")
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
                parsed = self._parse_netstat_s(out)
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
    return verdict, "；".join(text_bits), "\n".join(advice_bits)


class MonitorSession:
    """盯障会话: 4 路采集 + 进度行 + 网关漂移复查。"""

    PROBE_INTERVAL = 5.0      # TCP/DNS 探测周期
    GAP_S = 10.0              # ping 流静默判定间隙 (全丢包时超时行 ~2s/行)
    MIN_LOSS_BURST = 3        # 连续丢包 ≥3 (~3s) 判中断
    MIN_DNS_FAIL = 2          # DNS 连续失败 ≥2 (~10s) 判事件
    DNS_DOMAIN = "www.qq.com"

    def __init__(self, duration_s, ext_target=None):
        self.duration_s = duration_s
        self.ext_target = ext_target or "223.5.5.5"
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
        events = _detect_monitor_events(snap, self._t0, ended_at)
        verdict, conclusion, advice = _monitor_conclusion(events, stats, snap)

        t0 = self._t0
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
            "events": events,
            "verdict": verdict,
            "conclusion_text": conclusion,
            "advice": advice,
            "local_ip": get_local_ip(),
        }
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
        result["_csv_rows"] = rows
        outages = [e for e in events if e["type"] == "outage"]
        result["summary"] = (
            f"盯障 {duration_actual}s: 网关丢包 {stats['gw']['loss_pct']}%, "
            f"外网丢包 {stats['ext']['loss_pct']}%, "
            + (f"中断 {len(outages)} 起 (最长 "
               f"{max(e['duration_s'] for e in outages):.0f}s), "
               if outages else "无中断, ")
            + f"DNS 失败 {stats['dns']['fail']} 次")
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
    data_js = json.dumps({
        "gw": gw, "ext": ext,
        "gw_bands": _bands(samples.get("gw_loss") or []),
        "ext_bands": _bands(samples.get("ext_loss") or []),
        "tcp_rate": tcp_rate, "dns_rate": dns_rate,
    }, ensure_ascii=False)

    gw_pct = stats.get("gw", {}).get("loss_pct", 0)
    ext_pct = stats.get("ext", {}).get("loss_pct", 0)
    outages = [e for e in events if e["type"] == "outage"]
    longest = max((e["duration_s"] for e in outages), default=0)
    dns_ok = stats.get("dns", {}).get("ok_pct")

    def _metric(label, value, level, note=""):
        color = {"ok": "#0e8a4f", "warn": "#b26a00", "err": "#b42318"}[level]
        note_html = f"<div class='note'>{_esc_html(note)}</div>" if note else ""
        return (f"<div class='metric'><div class='lab'>{_esc_html(label)}</div>"
                f"<div class='v' style='color:{color}'>{_esc_html(value)}</div>"
                f"{note_html}</div>")

    v_color = {"stable": "#0e8a4f", "no_data": "#64748b", "target_unreachable": "#b26a00",
               "internal": "#b42318", "carrier": "#b42318", "dns": "#b26a00",
               "degraded": "#b26a00", "mixed": "#b42318"}.get(res.get("verdict"), "#0e8a4f")
    v_name = {"stable": "监测稳定", "no_data": "无有效数据", "target_unreachable": "目标不可达",
              "internal": "内网侧问题", "carrier": "运营商侧问题", "dns": "解析侧问题",
              "degraded": "质量劣化", "mixed": "混合问题"}.get(res.get("verdict"), "")

    ev_rows = []
    type_names = {"outage": "中断", "dns_fail": "DNS 故障", "tcp_fail": "TCP 失败",
                  "latency_spike": "延迟突增", "monitor_gap": "采集间隙"}
    cls_names = {"internal": "内网侧", "carrier": "运营商侧", "both_down": "内外同断",
                 "dns": "解析侧", "with_outage": "随中断", "policy": "端口策略",
                 "target_unreachable": "目标不可达", "unknown": "无法定位", "": ""}
    for e in events:
        if e["type"] == "monitor_gap":
            continue
        status = ("<span class='pill open'>结束时未恢复</span>" if e.get("open_at_end")
                  else "<span class='pill ok'>已恢复</span>")
        ev_rows.append(
            f"<tr><td>{_esc_html(e['start_disp'])}–{_esc_html(e['end_disp'])}</td>"
            f"<td>{e['duration_s']:.0f}s</td>"
            f"<td>{type_names.get(e['type'], e['type'])}</td>"
            f"<td>{_esc_html(cls_names.get(e.get('cls', ''), e.get('cls', '—')))}</td>"
            f"<td>{_esc_html(e.get('detail', ''))}</td><td>{status}</td></tr>")
    ev_table = ("<table><tr><th>时刻</th><th>持续</th><th>类型</th><th>定位</th>"
                "<th>详情</th><th>状态</th></tr>"
                + ("".join(ev_rows) if ev_rows
                   else "<tr><td colspan=6 class='empty'>监测期内无异常事件</td></tr>")
                + "</table>")

    notes_html = "".join(f"<div class='note-line'>· [{n['t']}s] {_esc_html(n['text'])}</div>"
                         for n in res.get("notes", []))
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>NetPulse 盯障监测报告</title>
<style>
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
</div>
<div class="banner">
<div class="verdict">{_esc_html(v_name)}</div>
<div class="text">{_esc_html(res.get('conclusion_text', ''))}</div>
<div class="advice">💡 处置建议: {_esc_html(res.get('advice', ''))}</div>
</div>
<div class="panel"><h3>事件明细 ({len([e for e in events if e['type'] != 'monitor_gap'])} 起)</h3>{ev_table}</div>
<div class="panel"><h3>延迟时序 (网关 / 外网, 红色区带 = 中断时段)</h3>
<canvas id="latChart" width="840" height="240"></canvas></div>
<div class="panel"><h3>连通率 (TCP 53 / DNS, 30 秒桶)</h3>
<canvas id="reachChart" width="840" height="160"></canvas></div>
<div class="panel"><h3>监测详情</h3>
<table>
<tr><th>项目</th><th>值</th></tr>
<tr><td>采样规格</td><td>网关/外网 ping 1s × 2 路; TCP 53 / DNS 解析 5s</td></tr>
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
</script>
</div></body></html>"""


def run_monitor_mode(duration_s, ext_target=None):
    """盯障模式入口 (CLI --monitor 与菜单 m 共用)。

    全文件唯一在长循环外层捕获 KeyboardInterrupt 的地方: Ctrl+C 提前结束
    也必须走统一的报告落盘路径 (装维随时可停, 数据不丢)。"""
    duration_s = max(30, min(86400, int(duration_s or 600)))
    session = MonitorSession(duration_s, ext_target)
    if not session.start():
        print(_c("  ✗ 外网 ping 启动失败, 无法开始监测 (检查 ping 命令可用性)", C_RED))
        return None
    tg = session  # noqa: F841 (保留引用便于将来扩展)
    print(_c(f"  盯障开始: 时长 {duration_s}s · 网关 {session._gw_ip or '—'} · "
             f"外网 {session._ext_ip_resolved} · DNS {session._dns_server}", C_CYAN))
    print(_c("  期间可正常使用电脑; Ctrl+C 可提前结束并生成报告", C_GRAY))
    early = False
    tty = sys.stdout.isatty()
    mono0 = time.monotonic()
    last_heartbeat = -61
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
    result = session.build_result(early_terminated=early)
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
    #    纯 info 级 issue 不改变状态 (与 HTML/PDF 卡片及顶部"需关注"口径一致,
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
    """Windows 下启用 ANSI 虚拟终端, 让旧版 cmd 也支持颜色"""
    if sys.platform != "win32":
        return
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        m = ctypes.c_ulong()
        k.GetConsoleMode(h, ctypes.byref(m))
        k.SetConsoleMode(h, m.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


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
        out = {k: v for k, v in res.items() if k != "callback"}
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
    return keys or None


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
    LAST_RUN = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "generated_at": datetime.now(),
        "system": sys_info,
        "status": dict(results),
        "results": full,
        "keys": list(keys),
    }
    return results


# ── 模块级超时 ──
# 旧版并行/顺序执行对单个模块没有超时: Speedtest 选服可拖数分钟、某些模块
# 卡死时会拖住整个诊断。现在每个模块在 daemon 线程里跑, 到点未完成即标记
# "超时"并继续, 不再互相拖累; daemon 线程也不会阻塞进程退出。
DEFAULT_MODULE_TIMEOUT = 120.0  # 秒
MODULE_TIMEOUTS = {
    "speedtest":   180.0,  # 国内HTTP(多源×多连接) + 可选 speedtest-cli + iperf3
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
    """在 daemon 线程中执行模块 detect(), 超时返回 ("超时", {error})。

    返回 (status, res_dict):
      - 正常完成: (determine_status(res), res)
      - 模块抛异常: ("错误", {"error": ...})
      - 超过 _module_timeout(key): ("超时", {"error": ...})
    超时后模块线程继续在后台运行 (daemon, 进程退出时被强杀), 结果被丢弃,
    不影响其它模块。
    """
    name, cls = MODULE_MAP[key]
    timeout = _module_timeout(key)
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
    box = {}

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
# SECTION: 诊断报告生成与导出 (TXT / HTML / PDF)
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
    return (f"网关 {gw}: 平均 {p.get('avg_ms', '?')}ms, "
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
            if issue.get("type") in ("gateway_packet_loss",):
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
    if "error" in res:
        # 顶层 error 时, 子模块里也可能有 error
        for k in ("speedtest", "http"):
            sub = res.get(k, {})
            if "error" in sub:
                return f"测速失败 ({k}): {sub['error']}"
        return res.get("error", "测速失败")
    return res.get("summary", "测速")


def _metrics_speedtest(res):
    """测速关键指标 (新结构: 顶层 download/upload/预估带宽/bufferbloat)"""
    out = []
    if "error" in res:
        return out
    down = res.get("download_mbps")
    up = res.get("upload_mbps")
    est = res.get("estimated_bandwidth") or {}
    grade = res.get("bufferbloat_grade") or ""
    idle = res.get("idle_rtt_ms")
    if down:
        out.append(("下载", f"{down} Mbps", "ok" if down >= 10 else "warn"))
    if up is not None:
        out.append(("上传", f"{up} Mbps", "ok" if up >= 5 else "warn"))
    if est.get("text"):
        out.append(("预估宽带", est["text"], "ok"))
    if idle is not None:
        out.append(("延迟(网关)", f"{idle:.0f} ms",
                    "ok" if idle < 30 else "warn"))
    if grade:
        lv = "ok" if grade.startswith(("A", "B")) else "warn"
        # 卡片只放等级字母 (A/B/...), 括号里的完整评语放 hint, 卡面更清爽
        g0 = grade.split(" ", 1)[0]
        g_rest = grade[len(g0):].strip(" ()")
        out.append(("缓冲膨胀", g0, lv, g_rest or "负载时延迟增加量"))
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
    """外网检测: 之前只亮徽章不出问题条目, 装维看不到处置建议 — 按段位给建议。"""
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
    if loss >= 5:
        out.append({"severity": "异常", "text": f"外网平均丢包 {loss}%",
                    "impact": "明显丢包: 网页卡顿、游戏掉线、视频花屏",
                    "action": "网关正常而此处丢包 → 问题在运营商侧, 保留报告 (含逐跳路径) 带回报障"})
    elif loss >= 1:
        out.append({"severity": "警告", "text": f"外网平均丢包 {loss}%",
                    "impact": "轻度丢包会影响游戏/通话体验",
                    "action": "结合网关模块丢包判断段位: 网关也丢=内网问题; 网关不丢=外线问题"})
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
                   "tech_keys": ["speedtest", "http"]},
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

def compute_health_score(counts, issues_count=None,
                          err_issue_count=None, fatal_issue_count=None,
                          warn_issue_count=None,
                          score_counts=None):
    """根据状态计数算健康分和等级。

    counts: {"完成": 14, "警告": 3, "异常": 1, ...}
    issues_count: 各模块实际 issue 总数 (含警告/异常/错误)。
                 若提供, verdict 文案会精确显示此项数。
    err_issue_count / fatal_issue_count / warn_issue_count:
                     真实各级 issue 数 (按实际 issue 统计)。
                     这些用于文案 (与 todo 列表一致), 默认含豁免模块。
    score_counts: 用于 score 实际扣分的 counts。默认 = counts (不含豁免)。
                  传入时可让豁免模块也参与扣分 (严) 或相反 (宽)。

    混合策略: 文案口径与扣分口径分离 — 让用户看到完整的异常数 (含豁免),
    同时 score 只反映用户能/应采取行动的问题 (不含豁免), 避免 ipv6 可选异常
    等被夸大。
    """
    # 评分口径:
    #   - 异常 -20, 错误 -30: 硬故障, 一票否决
    #   - 警告 -2: 仅提示, 不应压垮整体分数 (旧版 -5 偏重,
    #              1 异常 + 6 警告 = 50 分, 给人"网络不能用"的错觉)
    #   - 未检测不扣分: 环境缺测 (如无 WiFi 网卡) 不应被记过
    #   - 特殊豁免: 调用方可在 score_counts 里排除 iperf3/ipv6/proxy/nattype
    if err_issue_count is None:
        err_issue_count = counts.get("异常", 0)
    if fatal_issue_count is None:
        fatal_issue_count = counts.get("错误", 0)
    if warn_issue_count is None:
        warn_issue_count = counts.get("警告", 0)

    sc = score_counts if score_counts is not None else counts
    score = 100
    score -= sc.get("异常", 0) * 20
    score -= sc.get("错误", 0) * 30
    score -= sc.get("警告", 0) * 2
    score = max(0, min(100, score))

    # 文案所需的"异常/警告"计数一律基于真实 issue (而不是模块状态)
    err_cnt = err_issue_count + fatal_issue_count
    warn_cnt = warn_issue_count
    if issues_count is None:
        issues_count = err_cnt + warn_cnt

    # verdict 口径: 按模块状态计数 (与"检测结果一览"和统计卡一致)。
    # 之前按 issue 条目计数, 同一模块多条 issue 会被算成多项异常,
    # 导致"3 项异常"而一览里只有 1 个异常模块, 数字对不上。
    err_mod = counts.get("异常", 0) + counts.get("错误", 0)
    warn_mod = counts.get("警告", 0)
    for threshold, grade, label in HEALTH_GRADE_TABLE:
        if score >= threshold:
            if err_mod == 0 and warn_mod == 0:
                verdict = "网络良好, 无问题"
            elif err_mod > 0:
                verdict = f"{err_mod + warn_mod} 个模块需关注 (含 {err_mod} 个异常)"
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


def build_report():
    """基于最近一次诊断运行 (LAST_RUN) 构造完整报告数据结构 (双视图)。

    返回结构 (供 render_report_html_customer / render_report_pdf_customer / render_report_json 使用):
      {
        "app": ..., "version": ..., "generated_at": ...,
        "system": {local_ip, gateway, dns, public_ip, asn, geo, ipv6_public_ip},
        "health": {score, grade, label, verdict, counts},
        "summary": {key: status},  # 各模块状态 (老格式, 兼容)
        "counts": {完成: N, 警告: N, ...},  # 状态计数
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
    counts = {}
    exempt_count = 0
    for key, st in run["status"].items():
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

    # 汇总真实 issue 数 (按严重级别拆分, 用于 health.verdict 精确文案 + 分数)
    # 关键: 用真实 issue 计数, 不用 counts。counts 不含豁免模块, 但豁免模块里的
    # 真异常 issue (ipv6 不可达、外网丢包) 应该反映到 score/verdict。
    # 模块状态异常但没有任何非 info issue 时 (如 IPv6 状态异常 但 issues 全是 info)
    # 才补计 1 条模块级异常, 避免与 issue 条目重复计数。
    issue_total = 0
    err_issue_count = 0
    fatal_issue_count = 0
    warn_issue_count = 0
    for m in modules:
        for issue in m.get("issues", []) or []:
            sev = issue.get("severity", "信息")
            if sev == "异常":
                err_issue_count += 1
                issue_total += 1
            elif sev == "错误":
                fatal_issue_count += 1
                issue_total += 1
            elif sev == "警告":
                warn_issue_count += 1
                issue_total += 1
        # 模块状态异常但无对应 issue 条目, 补计 1 条 (但豁免模块跳过)
        # 否则 iperf3 未配置会算成 "1 项异常" 但用户看不到任何 issue, 自相矛盾
        if (m.get("key") not in EXEMPT_MODULES
                and not any(i.get("severity", "信息") in ("异常", "错误", "警告")
                            for i in (m.get("issues") or []))
                and m.get("status", "") in ("异常", "错误")):
            issue_total += 1
            err_issue_count += 1
    health = compute_health_score(
        counts, issues_count=issue_total,
        err_issue_count=err_issue_count,
        fatal_issue_count=fatal_issue_count,
        warn_issue_count=warn_issue_count,
    )

    return {
        "app": run["app"],
        "version": run["version"],
        "generated_at": run["generated_at"],
        "system": run["system"],
        "health": health,
        "counts": counts,
        "exempt_count": exempt_count,        # 评分豁免的模块数 (iperf3/ipv6/proxy/nattype)
        "summary": {m["key"]: m["status"] for m in modules},
        "modules": modules,
        "tech": {
            "raw_results": run["results"],
            "module_keys": run["keys"],
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
    order = ["完成", "警告", "异常", "错误", "未检测"]
    parts = [f"{k} {cnt[k]}" for k in order if cnt.get(k)]
    out.append(f"  共 {len(report['modules'])} 项: " + ", ".join(parts))
    if parts:
        ok_n = cnt.get("完成", 0)
        warn_n = cnt.get("警告", 0)
        err_n = cnt.get("异常", 0) + cnt.get("错误", 0)
        if err_n == 0 and warn_n == 0:
            verdict = "整体健康"
        elif err_n == 0:
            verdict = "整体正常，但有警告项"
        elif warn_n == 0:
            verdict = "存在异常项，建议排查"
        else:
            verdict = "存在异常与警告项，建议排查"
        out.append(f"  整体状态: {verdict}（正常 {ok_n} / 警告 {warn_n} / 异常 {err_n}）")
    out.append("")
    # 逐模块
    out.append("【详细结果】")
    for m in report["modules"]:
        out.append("-" * 64)
        out.append(f"◆ {m['name']}  [{m['status']}]")
        res = m["result"] or {}
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
    """渲染 HTML 报告 (专业工程风: 深色渐变页眉 + 统计卡 + 模块卡片 + 可折叠明细)。"""
    import html as _html

    if not report:
        return "<p>尚无诊断数据</p>"
    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")

    def _esc(s):
        return _html.escape(str(s), quote=False)

    # 状态 → 语义键 → (前景色, 浅底色)
    SKEY = {"完成": "ok", "警告": "warn", "异常": "err", "错误": "fatal",
            "未检测": "idle"}
    SC = {
        "ok":    ("#0e8a4f", "#e7f6ee"),
        "warn":  ("#b26a00", "#fdf3e3"),
        "err":   ("#d92d20", "#fdecec"),
        "fatal": ("#b42318", "#fbebea"),
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
    order = ["完成", "警告", "异常", "错误", "未检测"]
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
        res = m["result"] or {}
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


def ensure_reportlab(auto_yes=False, mirror=None):
    """确保 reportlab 可用 (PDF 导出依赖)。缺失时提示/自动安装。

    镜像选择: 走 _resolve_pip_mirror() 自动选源, 显式参数 mirror 仍可用作覆盖。

    frozen (PyInstaller EXE) 场景: 无法用 sys.executable -m pip 安装
    (sys.executable 是 EXE 本身, -m pip 无效且装到系统 Python 对 EXE 也不生效),
    直接返回 False 并给出明确提示, 由调用方降级 (如自动导出 HTML)。
    """
    try:
        import reportlab  # noqa
        return True
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        print(_c("  ⚠ 当前 EXE 版未内置 PDF 导出依赖 (reportlab)，无法导出 PDF。", C_YELLOW))
        print(_c("    将自动降级导出 HTML 报告；如需 PDF 请用内置 reportlab 的打包版。", C_YELLOW))
        return False
    is_tty = sys.stdout.isatty()
    if not is_tty and not auto_yes:
        print(_c("  ⚠ 未安装 reportlab，无法导出 PDF。可先运行一次交互模式安装，"
                 "或改用 --export report.html / report.txt。", C_YELLOW))
        return False
    print(_c("  正在准备 PDF 导出依赖 reportlab ...", C_GRAY))
    if mirror is None:
        mirror, source = _resolve_pip_mirror()
        if mirror:
            print(_c(f"  自动选源: {mirror} ({source})", C_GRAY))
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "reportlab"]
    if mirror:
        cmd += ["-i", mirror]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              env=os.environ.copy(), timeout=300)
    except subprocess.TimeoutExpired:
        print(_c("  ✗ reportlab 安装超时", C_RED)); return False
    except Exception as e:
        print(_c(f"  ✗ reportlab 安装异常: {e}", C_RED)); return False
    if proc.returncode != 0:
        print(_c("  ✗ reportlab 安装失败:", C_RED))
        for line in (proc.stdout + proc.stderr).strip().split("\n")[-10:]:
            if line.strip():
                print(_c("    " + line.strip(), C_GRAY))
        return False
    print(_c("  ✓ reportlab 安装成功", C_GREEN))
    return True


def _flatten_kv(v, prefix=""):
    """将嵌套 dict/list 扁平化为 (key, value) 列表，便于 PDF/HTML 表格展示。

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
}


def _record_table(v):
    """若 v 是同构字典列表(记录表), 返回 (headers, rows); 否则返回 None。

    headers/rows 均为已中文化/字符串化的列表, 可直接交给 PDF/HTML 渲染。
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
      - "ZeroTier One [9f77fc393e225015]" (31字符) 也完整保留
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
    """HTML escape, 中文和空格安全。"""
    import html as _html
    if s is None:
        return ""
    return _html.escape(str(s), quote=False)


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
                    rows.append((_html_esc(HEADER_MAP.get(kk, kk)),
                                 _html_esc(json.dumps(vv, ensure_ascii=False)[:200])))
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
                v = json.dumps(v, ensure_ascii=False)
            parts.append(f"{k}: {v}")
        s = ", ".join(parts)
        return s if len(s) <= max_len else s[:max_len - 1] + "…"
    except Exception:
        return json.dumps(d, ensure_ascii=False)[:max_len]


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
    return (f"<div class='subcap'>探测目标 ({len(targets)} 条, 仅展示关键列; "
            f"证书/重定向等完整字段见 JSON 报告)</div>"
            f"<div class='tbl-wrap'><table class='tbl'><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table></div>")


def _render_linkspeed_adapters_table(adapters):
    """链路速率专用: 只展示真正有用的 5 列。

    原 _record_table 把 adapters dict 的全部 12 个 key 都展开, 导致:
      - 重复列 (链路速率原始值 / 速率 Mbps / 综合判定 含相同信息)
      - 冗余列 (4 个收发包错误列几乎都是 0/N/A)
      - 难懂列 (无线网卡 True/False、媒体类型 802.3/Native 802.11)
      - 长名 (ZeroTier One [9f77fc393e225015] + Realtek 8822CE ...) 把表格撑爆
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


def render_report_html_customer(report):
    """渲染客户版 HTML 报告。

    输入: build_report() 的输出 (双视图)
    输出: 完整可独立打开的 HTML 字符串
    """
    # 评分卡配色: 90+=绿, 70-89=橙, <70=红
    def _score_class(score):
        if score >= 90:
            return "score-90"
        elif score >= 80:
            return "score-80"
        elif score >= 70:
            return "score-70"
        elif score >= 60:
            return "score-60"
        else:
            return "score-50"

    if not report:
        return "<p>尚无诊断数据，请先运行诊断</p>"

    import html as _html
    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")
    sys_i = report["system"]
    health = report["health"]
    counts = report["counts"]
    modules = report["modules"]

    # 状态色
    SKEY = {"完成": "ok", "警告": "warn", "异常": "err", "错误": "fatal", "未检测": "idle"}
    SC = {"ok": "#16a34a", "warn": "#ea580c", "err": "#dc2626", "fatal": "#7f1d1d", "idle": "#94a3b8"}

    # ── 顶部 hero ──
    geo_line = ""
    if sys_i.get("asn") or sys_i.get("geo"):
        geo_bits = []
        if sys_i.get("geo"):
            geo_bits.append(sys_i["geo"])
        if sys_i.get("asn"):
            geo_bits.append(sys_i["asn"])
        geo_line = f"<div class='chips'><span class='chip'>📍 {' / '.join(geo_bits)}</span></div>"
    ipv6_line = ""
    if sys_i.get("ipv6_public_ip"):
        ipv6_line = (f"<div class='chips'><span class='chip'>"
                     f"IPv6: {_html_esc(sys_i['ipv6_public_ip'])}</span></div>")

    host_line = f"本机 {_html_esc(sys_i.get('local_ip', '?'))} · 公网 {_html_esc(sys_i.get('public_ip', '?'))}"
    if sys_i.get("dns"):
        host_line += f" · DNS {_html_esc(sys_i['dns'])}"

    hero = f"""
<header class="hero">
  <div class="hero-left">
    <div class="brand"><span class="logo"></span>
      <span class="brand-name">{_html_esc(report['app'])}</span>
      <span class="ver">v{_html_esc(report['version'])}</span></div>
    <h1>网络诊断报告</h1>
    <div class="sub">生成于 {_html_esc(g)}</div>
    <div class="chips"><span class="chip">{host_line}</span></div>
    {geo_line}
    {ipv6_line}
  </div>
  <div class="score {_html_esc(_score_class(health["score"]))}">
    <div class="score-num">{health['score']}</div>
    <div class="score-label">{_html_esc(health['verdict'])}</div>
  </div>
</header>"""

    # ── 待办问题 ──
    # 1) 收集所有 issue; 2) 按 (severity, text) 去重避免多模块重复同一警告;
    # 3) 顶部列表只展示异常/错误/警告, 信息级不进顶部 (详情里仍可见)
    todo_issues = []
    seen_keys = set()
    for m in modules:
        for issue in m.get("issues", []) or []:
            text = (issue.get("text", "") or "").strip()
            dedup_key = (issue.get("severity", "信息"), text)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            todo_issues.append({**issue, "_module": m["name"], "_status": m["status"]})

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
                merged[merge_index[gkey]]["_texts"].append(issue.get("text", ""))
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
<div class="sec"><h2><span class="icon">⚠</span>{len(need_attention)} 项需要您关注{info_extra}</h2></div>
<div class="todo">{"".join(todo_blocks)}</div>"""
    elif todo_issues:
        todo_section = """
<div class="sec"><h2><span class="icon">✓</span>所有核心检测通过</h2></div>
<div class="todo ok">
  <div class="todo-head">✓ 网络状态良好</div>
  <div class="impact">所有核心检测均正常, 部分提示项可在下方模块详情查看。</div>
</div>"""
    else:
        todo_section = f"""
<div class="sec"><h2><span class="icon">✓</span>所有检测通过</h2></div>
<div class="todo ok">
  <div class="todo-head">✓ 网络状态良好</div>
  <div class="impact">全部 {len(modules)} 项检测均正常, 无需特别处理。</div>
</div>"""

    # ── 统计卡片 ──
    stats_order = ["完成", "警告", "异常", "错误", "未检测"]
    stat_items = [(k, counts.get(k, 0)) for k in stats_order if counts.get(k, 0)]
    if not stat_items:
        stat_items = [("未检测", 0)]
    stat_cards = "".join(
        f"<div class='stat-card {SKEY.get(k, 'idle').replace('fatal', 'err')}'>"
        f"<div class='count'>{v}</div>"
        f"<div class='label'>{k}</div></div>"
        for k, v in stat_items
    )
    # 模块总数 + 豁免模块数 (避免 stats-grid 只显示 17+1 误导用户以为只剩 18 个模块)
    total_modules = len(modules)
    exempt_count = report.get("exempt_count", 0) or 0
    stats_caption = ""
    if total_modules:
        if exempt_count:
            stats_caption = f"<div class='stats-caption'>共 {total_modules} 个模块 (含 {exempt_count} 个评分豁免: iperf3/ipv6/proxy/nattype, 不参与扣分)</div>"
        else:
            stats_caption = f"<div class='stats-caption'>共 {total_modules} 个模块</div>"
    stats_section = f"""
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
            f"<a href='#mod-{_html_esc(m['key'])}' title='跳转到 {_html_esc(m['name'])} 详细结果'>"
            f"<span class='dot {sk}'></span>"
            f"<span class='name'>{_html_esc(m['name'])}</span>"
            f"<span class='verdict'>{_html_esc(verdict_short)}</span>"
            f"<span class='badge {sk}'>{_html_esc(st)}</span>"
            f"</a>"
            f"</li>"
        )
    overview_section = f"""
<div class="sec"><h2><span class="icon">📋</span>检测结果一览</h2></div>
<div class="overview"><ul>{"".join(overview_items)}</ul></div>"""

    # ── 详细模块 ──
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
                # 统计卡保持清爽: 正常指标的说明只进悬停提示, 不占卡面;
                # 只有 warn/err (需要用户注意) 的指标才把说明显示在卡面上
                hint_html = (f"<span class='hint'>{_html_esc(hint)}</span>"
                             if hint and level in ("warn", "err") else "")
                # title 提示完整名/值/说明, 防止窄屏 ellipsis 截断后看不到原值
                full_title = f"{me.get('label','')}: {me.get('value','')}"
                if hint:
                    full_title += f"\n{hint}"
                # 数值在上、名称在下 (flex-column), 长名称可换行不再截断
                metric_html.append(
                    f"<div class='metric' title='{_html_esc(full_title)}'>"
                    f"<span class='v {level}'>{_html_esc(me['value'])}</span>"
                    f"<span class='lab'>{_html_esc(me['label'])}</span>"
                    f"{hint_html}"
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

        # 技术细节折叠 (默认展开, 便于装维留档时一眼看全; 用户可手动折叠)
        tech_html = ""
        if m.get("has_tech_details"):
            pres = MODULE_PRESENTATION.get(m["key"], {})
            tech_keys = pres.get("tech_keys", [])
            tech_html = _render_html_tech_block(
                m["key"], m.get("raw", {}), tech_keys, auto_open=True)

        # WiFi 等模块原始数据全空时, 给出友好提示而非空列表
        empty_note_html = ""
        if m["key"] == "wifi":
            raw = m.get("raw", {}) or {}
            nets = raw.get("networks") or []
            chans = raw.get("channel_analysis") or []
            if not nets and not chans:
                empty_note_html = "<div class='impact-line warn'><b>[提示]</b> 当前未连接 Wi-Fi, 因此未扫描周边网络与信道占用 (这是正常现象, 而非故障)。</div>"

        # 整个模块卡
        verdict = m.get("verdict", "")
        explain = MODULE_EXPLAINS.get(m["key"], "")
        explain_html = (f"<div class='explain'>📖 {_html_esc(explain)}</div>"
                        if explain else "")
        # 模块图标
        mod_icons = {
            "ok": "✓",
            "warn": "⚠",
            "err": "✕",
            "fatal": "✕",
            "idle": "○"
        }
        mod_icon = mod_icons.get(sk, "○")
        mod_blocks.append(f"""
<div class="mod {sk}" id="mod-{_html_esc(m["key"])}">
  <div class="mod-head">
    <div class="mod-icon {sk}">{mod_icon}</div>
    <div class="name">{_html_esc(m['name'])}<a class="anchor" href="#mod-{_html_esc(m["key"])}" title="复制此模块链接" aria-label="复制 {_html_esc(m['name'])} 模块链接">🔗</a></div>
    <span class="badge {sk}">{_html_esc(st)}</span>
  </div>
  <div class="mod-body">
    <div class="verdict"><span class="tag">结论</span>{_html_esc(verdict)}</div>
    {explain_html}
    {metrics_html}
    {issues_html}
    {empty_note_html}
    {tech_html}
  </div>
</div>""")

    modules_section = f"""
<div class="sec"><h2><span class="icon">🔍</span>详细结果</h2></div>
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
<div class="sec"><h2><span class="icon">🖥</span>主机信息</h2></div>
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
    standards_section = f"""
<div class="sec"><h2><span class="icon">📐</span>本报告诊断标准</h2></div>
<details class="collapse" data-auto-open="0"><summary>查看判定阈值与口径 <span class='cnt'>{len(standards_rows)} 项指标</span></summary>
<div class="body">
  <div class='subcap'>判定规则: "越低越差"的指标 (延迟/丢包/重传/抖动), 超过<span class='kw warn'>警告阈值</span>标 ⚠️ 警告, 超过<span class='kw err'>异常阈值</span>标 ❌ 异常; "越高越好"的指标 (速率/TCP 可达数), 低于警告阈值标警告, 低于异常阈值标异常。所有阈值集中维护在 <code>THRESHOLDS</code>, 链路速率另在 <code>_metrics_linkspeed</code> 硬编码。</div>
  <table class='tbl std'>
    <thead><tr><th>模块</th><th>指标</th><th>警告阈值</th><th>异常阈值</th><th>单位</th><th>判定方向</th></tr></thead>
    <tbody>{std_body}</tbody>
  </table>
  <div class='subcap' style='margin-top:12px'>评分规则: 起始 100 分, 异常 -20/项, 错误 -30/项, 警告 -2/项, 未检测不扣分。<br>豁免模块 (不参与扣分): iperf3(未配置非故障), IPv6(可选), VPN/虚拟网卡(环境特性), NAT类型(运营商侧)。等级: A≥90 优秀, B≥75 良好, C≥60 一般, D≥40 欠佳, F&lt;40 严重。</div>
</div>
</details>"""

    # ── CSS ──
    CSS = """
*{box-sizing:border-box;margin:0;padding:0;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.skip-link{position:absolute;left:-9999px;top:0;z-index:9999;background:#0a1628;color:#fff;padding:8px 16px;text-decoration:none;border-radius:0 0 8px 0}
.skip-link:focus{left:0}
@media (prefers-reduced-motion: reduce){
*{animation:none!important;transition:none!important}
}
/* 报告需可离线打开: 全部使用系统字体, 不引入任何在线资源 */
body{background:linear-gradient(180deg,#f8fafc 0%,#e2e8f0 100%);color:#1e293b;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;padding:32px 16px 80px}
.wrap{max-width:900px;margin:0 auto}
.hero{background:linear-gradient(135deg,#0b1f3a 0%,#153e6b 55%,#1d4e89 100%);color:#fff;padding:36px 40px;display:grid;grid-template-columns:1fr auto;gap:32px;align-items:center;border-radius:20px;box-shadow:0 12px 32px -12px rgba(11,31,58,.45);margin-bottom:28px;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:-50%;right:-15%;width:420px;height:420px;background:radial-gradient(circle,rgba(96,165,250,.22) 0%,transparent 70%);pointer-events:none}
.hero h1{font-size:26px;font-weight:800;letter-spacing:.5px;margin:10px 0 4px}
.hero .brand{display:flex;align-items:center;gap:9px}
.hero .logo{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,#7ab3f5,#3b82f6);display:inline-block;position:relative;flex:none}
.hero .logo::after{content:'';position:absolute;inset:6px;border:2px solid rgba(255,255,255,.92);border-radius:3px}
.hero .brand-name{font-size:15px;font-weight:700;color:#dbeafe;letter-spacing:.3px}
.hero .ver{font-size:11px;font-weight:600;color:#bfdbfe;background:rgba(255,255,255,.14);padding:1px 9px;border-radius:999px}
.hero .sub{font-size:13px;color:#9db8dd;margin-bottom:14px}
.hero .chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.hero .chip{font-size:12px;color:#cfe0f5;background:rgba(255,255,255,.09);border:1px solid rgba(255,255,255,.14);border-radius:999px;padding:3px 12px;font-family:'JetBrains Mono',Cascadia Mono,Consolas,monospace}
.score{background:rgba(255,255,255,.1);backdrop-filter:blur(20px);border-radius:16px;padding:22px 30px;text-align:center;min-width:150px;border:1px solid rgba(255,255,255,.22);position:relative;z-index:1}.score.score-90{background:linear-gradient(135deg,rgba(16,185,129,.3),rgba(5,150,105,.4))}.score.score-80{background:linear-gradient(135deg,rgba(16,185,129,.25),rgba(5,150,105,.35))}.score.score-70{background:linear-gradient(135deg,rgba(245,158,11,.3),rgba(217,119,6,.4))}.score.score-60,.score.score-50{background:linear-gradient(135deg,rgba(239,68,68,.35),rgba(220,38,38,.45))}
.score-num{font-size:56px;font-weight:900;line-height:1;font-variant-numeric:tabular-nums}
.score.score-90 .score-num{color:#34d399}.score.score-80 .score-num{color:#6ee7b7}.score.score-70 .score-num{color:#fbbf24}.score.score-60 .score-num,.score.score-50 .score-num{color:#f87171}
.score-label{font-size:13px;opacity:.9;margin-top:4px}
.sec{margin:32px 0 12px}
.sec h2{font-size:18px;font-weight:700;display:flex;align-items:center;gap:8px;color:#111827}
.sec h2 .icon{width:28px;height:28px;border-radius:8px;background:#e0e7ff;color:#4338ca;display:inline-flex;align-items:center;justify-content:center;font-size:14px}.sec h2 .extra-count{font-size:12px;font-weight:400;color:#64748b;margin-left:6px}
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:8px}
.stats-caption{text-align:center;font-size:11.5px;color:#94a3b8;margin-bottom:24px}
.stat-card{background:#fff;border-radius:12px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e5e7eb;transition:transform .2s,box-shadow .2s}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.12)}
.stat-card .count{font-size:32px;font-weight:800}
.stat-card.ok .count{color:#10b981}.stat-card.warn .count{color:#f59e0b}.stat-card.err .count,.stat-card.danger .count{color:#ef4444}.stat-card.info .count{color:#6b7280}
.stat-card .label{font-size:12px;color:#9ca3af;margin-top:2px}
.todo{background:#fff;border-radius:20px;padding:24px;margin-bottom:32px;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e5e7eb}
.todo.ok{background:linear-gradient(180deg,#f0fdf4 0%,#f7fee7 100%);border-color:#bbf7d0}
.todo-head{font-size:15px;font-weight:700;color:#991b1b;margin-bottom:12px}
.todo.ok .todo-head{color:#166534}
.issue{padding:12px 0;border-top:1px dashed #fecaca}
.issue:first-of-type{border-top:none;padding-top:0}
.issue.ok{border-top-color:#bbf7d0}
.issue h3{font-size:14.5px;font-weight:700;color:#7f1d1d;margin-bottom:4px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.issue.ok h3{color:#166534}
.issue .sev{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;background:#dc2626;color:#fff}
.issue.warn .sev{background:#ea580c}
.issue.info .sev{background:#64748b}
.issue .meta{font-size:11.5px;color:#94a3b8;margin-bottom:6px}
.issue .impact{font-size:12.5px;color:#991b1b;margin:4px 0 6px;padding:6px 10px;background:rgba(255,255,255,.6);border-radius:6px}
.issue.ok .impact{color:#166534}
.issue .action{font-size:12.5px;color:#1e293b;padding:8px 12px;background:#fffbeb;border-left:3px solid #f59e0b;border-radius:0 6px 6px 0;line-height:1.7}
.issue.consult{border-top:1px dashed #fecaca}
.overview{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:6px 0;margin-bottom:8px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
.overview ul{list-style:none}
.overview li{padding:0;border-bottom:1px solid #f1f5f9;font-size:13.5px}
.overview li:last-child{border-bottom:none}
.overview li a{padding:10px 22px;display:flex;align-items:center;gap:12px;color:inherit;text-decoration:none;transition:background .1s}
.overview li a:hover{background:#f8fafc}
.overview li a:hover .name{color:#2563eb}
.overview li:last-child{border-bottom:none}
.overview .name{font-weight:600;min-width:130px;color:#0f172a}
.overview .verdict{color:#475569;flex:1;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.overview .badge{padding:2px 11px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.5px;flex:none}
.badge.ok{background:#dcfce7;color:#15803d}
.badge.warn{background:#fed7aa;color:#9a3412}
.badge.err{background:#fecaca;color:#991b1b}
.badge.fatal{background:#7f1d1d;color:#fff}
.badge.idle{background:#e2e8f0;color:#475569}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.dot.ok{background:#16a34a}.dot.warn{background:#ea580c}.dot.err{background:#dc2626}.dot.fatal{background:#7f1d1d}.dot.idle{background:#94a3b8}
.mod{background:#fff;border:1px solid #e2e8f0;border-radius:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e5e7eb;overflow:hidden;transition:box-shadow .2s}
.mod:hover{box-shadow:0 4px 12px rgba(0,0,0,.1)}
.mod-head{padding:16px 24px;display:flex;align-items:center;gap:16px;border-bottom:1px solid #f3f4f6;background:#fafbfc}
.mod-icon{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:20px}
.mod-icon.ok{background:#d1fae5}.mod-icon.warn{background:#fef3c7}.mod-icon.err{background:#fee2e2}.mod-icon.info{background:#f3f4f6}
.mod-head .name{font-size:16px;font-weight:700;color:#111827;flex:1}.mod-head .subtitle{font-size:12px;color:#9ca3af}
.mod-head a.anchor{color:#94a3b8;font-size:13px;text-decoration:none;margin-left:6px}.mod-head a.anchor:hover{color:#2563eb}.mod{scroll-margin-top:80px}
.mod-head .badge{margin-left:auto;padding:4px 14px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.5px}
.mod-body{padding:24px}
.verdict{font-size:14px;line-height:1.7;color:#1e293b;margin-bottom:12px}
.explain{font-size:12px;line-height:1.7;color:#64748b;background:#f8fafc;border-left:3px solid #cbd5e1;padding:7px 12px;border-radius:0 6px 6px 0;margin:-4px 0 12px 0}
.verdict .tag{display:inline-block;padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700;background:#e0e7ff;color:#4338ca;margin-right:8px;vertical-align:1px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-bottom:8px}
.metric{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 13px;display:flex;flex-direction:column;align-items:flex-start;gap:3px;min-width:0}
.metric .v{font-size:15px;font-weight:700;font-family:Cascadia Mono,Consolas,monospace;text-align:left;max-width:100%;overflow-wrap:break-word}
.metric .lab{font-size:11.5px;color:#64748b;overflow-wrap:break-word;white-space:normal;line-height:1.45;max-width:100%}
.metric .v.ok{color:#15803d}.metric .v.warn{color:#c2410c}.metric .v.err{color:#b91c1c}.metric .v.info{color:#64748b}.metric .v.idle{color:#94a3b8}
.metric .hint{font-size:11px;color:#b45309;font-weight:400;display:block;margin-top:2px;line-height:1.45}
.impact-line{background:#fef2f2;border-left:3px solid #dc2626;padding:6px 12px;border-radius:0 6px 6px 0;font-size:12.5px;color:#7f1d1d;margin:8px 0}
.impact-line.warn{background:#fffbeb;border-left-color:#f59e0b;color:#78350f}.impact-line.info{background:#f1f5f9;border-left-color:#94a3b8;color:#475569;font-size:12px}
.action-line{background:#f0f9ff;border-left:3px solid #0284c7;padding:6px 12px;border-radius:0 6px 6px 0;font-size:12.5px;color:#0c4a6e;margin:4px 0 8px;line-height:1.6}
details.collapse{margin-top:10px;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:8px}details.collapse[data-auto-open="1"]{border-style:solid;border-color:#cbd5e1}
details.collapse summary{padding:9px 14px;font-size:12.5px;color:#475569;cursor:pointer;font-weight:600;user-select:none;list-style:none;display:flex;align-items:center;gap:6px}
details.collapse summary::-webkit-details-marker{display:none}
details.collapse summary::before{content:"▸";color:#64748b;transition:transform .15s;display:inline-block}
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
.host-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}
.host-card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:11px 14px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
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
@media(max-width:768px){.hero{grid-template-columns:1fr;text-align:center;padding:32px}.score{justify-self:center}.stats-grid{grid-template-columns:repeat(3,1fr)}.speed-stats{grid-template-columns:repeat(2,1fr)}.hero .meta{justify-content:center}}
@media print{body{background:#fff;padding:0;font-size:12px}.hero{background:#1e3a8a !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.mod,.host-card,.todo{box-shadow:none;break-inside:avoid}.mod-head{break-after:avoid}details.collapse .body{display:block !important}details.collapse>summary::before{display:none}details.collapse{border-style:solid}.score{background:rgba(255,255,255,.2) !important}}
footer{text-align:center;color:#94a3b8;font-size:12px;margin-top:36px;padding-top:20px;border-top:1px solid #e2e8f0}
"""

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
<div class="wrap">
<main id="main-content">
{hero}
{todo_section}
{stats_section}
{overview_section}
{modules_section}
{host_section}
{standards_section}
</main>
<footer>由 {_html_esc(report['app'])} v{_html_esc(report['version'])} 自动生成 · {_html_esc(g)}</footer>
</div>
<script>
// IP/MAC 值点击复制
(function(){{
  document.querySelectorAll('.host-card .val').forEach(function(el){{
    el.addEventListener('click', function(){{
      var txt = el.textContent.trim();
      if (!txt || txt === '—') return;
      if (navigator.clipboard && navigator.clipboard.writeText){{
        navigator.clipboard.writeText(txt).then(function(){{
          var orig = el.textContent;
          el.textContent = '✓ 已复制';
          el.classList.add('copied');
          setTimeout(function(){{ el.textContent = orig; el.classList.remove('copied'); }}, 1200);
        }}).catch(function(){{ fallbackCopy(txt, el); }});
      }} else {{
        fallbackCopy(txt, el);
      }}
    }});
    el.title = '点击复制: ' + el.textContent.trim();
  }});
  function fallbackCopy(txt, el){{
    var ta = document.createElement('textarea');
    ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try {{ document.execCommand('copy'); }} catch(e) {{}}
    document.body.removeChild(ta);
    var orig = el.textContent;
    el.textContent = '✓ 已复制';
    el.classList.add('copied');
    setTimeout(function(){{ el.textContent = orig; el.classList.remove('copied'); }}, 1200);
  }}
}})();
</script>
</body>
</html>"""


def _register_pdf_cjk_font():
    """注册 PDF 中文字体: 优先微软雅黑 (TTF 内嵌, 无阅读器字体依赖),
    缺失/失败时回退 STSong-Light (CID 宋体, 不内嵌)。

    返回 (font_name, has_bold):
      - font_name: 报告正文/标题统一使用的字体名
      - has_bold: 是否注册了独立粗体 (True 时 <b> 会真正加粗)
    """
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    windir = os.environ.get("WINDIR") or r"C:\Windows"
    fonts_dir = os.path.join(windir, "Fonts")
    regular = os.path.join(fonts_dir, "msyh.ttc")
    bold = os.path.join(fonts_dir, "msyhbd.ttc")
    try:
        if os.path.exists(regular):
            pdfmetrics.registerFont(TTFont("MSYaHei", regular, subfontIndex=0))
            if os.path.exists(bold):
                pdfmetrics.registerFont(
                    TTFont("MSYaHei-Bold", bold, subfontIndex=0))
                pdfmetrics.registerFontFamily(
                    "MSYaHei", normal="MSYaHei", bold="MSYaHei-Bold",
                    italic="MSYaHei", boldItalic="MSYaHei-Bold")
                return "MSYaHei", True
            # 无粗体文件: 常规字重同时充当粗体 (保证中文正常渲染)
            pdfmetrics.registerFontFamily(
                "MSYaHei", normal="MSYaHei", bold="MSYaHei",
                italic="MSYaHei", boldItalic="MSYaHei")
            return "MSYaHei", False
    except Exception:
        pass
    # 回退: 宋体 CID 字体 (不内嵌, 依赖阅读器内置字体)
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    return "STSong-Light", False


def render_report_pdf(report, path, auto_install=False, pip_mirror=None):
    """客户版 PDF 报告 (浅色主题 + 模块卡片, 内置中文字体微软雅黑)。

    与老版的差异:
      - 用 build_report 的双视图 (customer_view + tech_view), 不再吃 raw result
      - 每模块: 状态徽章 + 结论 + 3-5 个关键指标 + 问题/建议
      - PDF 不能折叠, 技术细节弱化为浅灰小表 (工程师看 JSON 拿完整数据)
      - 顶部加健康分大字, 待办问题单独成块

    auto_install: True 时 reportlab 缺失会自动 pip install
    pip_mirror: 显式指定 pip 镜像 URL
    """
    if not ensure_reportlab(auto_yes=auto_install, mirror=pip_mirror):
        return False
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame,
                                    Paragraph, Spacer, Table, TableStyle,
                                    KeepTogether, HRFlowable, CondPageBreak)

    FONT, _has_bold = _register_pdf_cjk_font()

    # ── 配色 (与 HTML 客户版一致) ──
    C_INK = colors.HexColor("#1e293b")
    C_SUB = colors.HexColor("#64748b")
    C_FAINT = colors.HexColor("#94a3b8")
    C_LINE = colors.HexColor("#e2e8f0")
    C_CARD = colors.HexColor("#f6f8fa")
    C_BAND = colors.HexColor("#1e3a8a")
    C_PRI = colors.HexColor("#2563eb")
    C_PRI_DEEP = colors.HexColor("#1e40af")
    C_PRI_SOFT = colors.HexColor("#dbeafe")
    C_OK = colors.HexColor("#16a34a")
    C_WARN = colors.HexColor("#ea580c")
    C_ERR = colors.HexColor("#dc2626")
    C_FATAL = colors.HexColor("#7f1d1d")
    C_IDLE = colors.HexColor("#94a3b8")
    SC = {"完成": C_OK, "警告": C_WARN, "异常": C_ERR, "错误": C_FATAL,
          "未检测": C_IDLE}
    SC_HEX = {"完成": "#16a34a", "警告": "#ea580c", "异常": "#dc2626",
              "错误": "#7f1d1d", "未检测": "#94a3b8"}
    SC_SOFT = {"完成": "#dcfce7", "警告": "#fed7aa", "异常": "#fecaca",
               "错误": "#fecaca", "未检测": "#e2e8f0"}

    # ── 样式 ──
    h_title = ParagraphStyle("h_title", fontName=FONT, fontSize=18,
                             textColor=colors.white, leading=22, spaceAfter=0)
    h_sub = ParagraphStyle("h_sub", fontName=FONT, fontSize=8.5,
                           textColor=colors.HexColor("#9db8e8"), leading=12)
    h_score = ParagraphStyle("h_score", fontName=FONT, fontSize=26,
                             textColor=colors.white, leading=30, alignment=1)
    h_score_lbl = ParagraphStyle("h_score_lbl", fontName=FONT, fontSize=9,
                                 textColor=colors.HexColor("#c6d6f0"), leading=12,
                                 alignment=1)
    sec = ParagraphStyle("sec", fontName=FONT, fontSize=13,
                         textColor=C_INK, leading=17, spaceBefore=12, spaceAfter=6)
    lbl = ParagraphStyle("lbl", fontName=FONT, fontSize=9,
                         textColor=C_SUB, leading=13)
    val = ParagraphStyle("val", fontName=FONT, fontSize=9.5, textColor=C_INK, leading=13)
    val_bold = ParagraphStyle("val_bold", fontName=FONT, fontSize=10,
                              textColor=C_INK, leading=13, fontWeight="bold")
    mod_title = ParagraphStyle("mt", fontName=FONT, fontSize=11.5,
                               textColor=C_INK, leading=15)
    mod_sub = ParagraphStyle("ms", fontName=FONT, fontSize=9,
                            textColor=C_SUB, leading=13, spaceBefore=2)
    th = ParagraphStyle("th", fontName=FONT, fontSize=8.5,
                        textColor=C_PRI_DEEP, leading=12)
    cell = ParagraphStyle("cell", fontName=FONT, fontSize=8.5,
                          textColor=C_INK, leading=12)
    concl = ParagraphStyle("concl", fontName=FONT, fontSize=9.5,
                           textColor=C_INK, leading=14)
    err_style = ParagraphStyle("err", fontName=FONT, fontSize=9,
                               textColor=C_ERR, leading=13, spaceBefore=1)
    warn_style = ParagraphStyle("warn", fontName=FONT, fontSize=9,
                                textColor=C_WARN, leading=13, spaceBefore=1)
    action_style = ParagraphStyle("act", fontName=FONT, fontSize=8.5,
                                  textColor=colors.HexColor("#0c4a6e"),
                                  leading=12, spaceBefore=1)
    badge_style = ParagraphStyle("badge", fontName=FONT, fontSize=8.5,
                                 textColor=colors.white, leading=11, alignment=1)
    detail_cap = ParagraphStyle("detail_cap", fontName=FONT, fontSize=8,
                                textColor=C_FAINT, leading=11, spaceBefore=2)
    detail_sec = ParagraphStyle("detail_sec", fontName=FONT, fontSize=8,
                                textColor=C_SUB, leading=11, spaceBefore=3,
                                spaceAfter=1)
    tech_cell = ParagraphStyle("tech_cell", fontName=FONT, fontSize=7.5,
                               textColor=C_INK, leading=10)
    metric_lbl = ParagraphStyle("mlbl", fontName=FONT, fontSize=8.5,
                                textColor=C_SUB, leading=12)
    metric_val_ok = ParagraphStyle("mv_ok", fontName=FONT, fontSize=10,
                                  textColor=C_OK, leading=13, alignment=0)
    metric_val_warn = ParagraphStyle("mv_warn", fontName=FONT, fontSize=10,
                                    textColor=C_WARN, leading=13, alignment=0)
    metric_val_err = ParagraphStyle("mv_err", fontName=FONT, fontSize=10,
                                   textColor=C_ERR, leading=13, alignment=0)
    metric_val_idle = ParagraphStyle("mv_idle", fontName=FONT, fontSize=10,
                                     textColor=C_IDLE, leading=13, alignment=0)
    metric_val_map = {"ok": metric_val_ok, "warn": metric_val_warn,
                      "err": metric_val_err, "idle": metric_val_idle}

    def _badge(status, width=24 * mm):
        c = SC_HEX.get(status, "#57606a")
        t = Table([[Paragraph(f"<b>{status}</b>", badge_style)]], colWidths=[width])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(c)),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        return t

    def _stat_cards(cnt):
        order = ["完成", "警告", "异常", "错误", "未检测"]
        items = [(k, cnt.get(k, 0)) for k in order if cnt.get(k, 0)]
        if not items:
            items = [("未检测", 0)]
        n = len(items)
        cw = content_w / n
        row = []
        for k, v in items:
            soft = colors.HexColor(SC_SOFT.get(k, "#f1f3f7"))
            fg = colors.HexColor(SC_HEX.get(k, "#8a94a6"))
            sn = ParagraphStyle("sn", fontName=FONT, fontSize=17,
                                textColor=fg, leading=21, alignment=1)
            sl = ParagraphStyle("sl", fontName=FONT, fontSize=8.5,
                                textColor=fg, leading=11, alignment=1)
            inner = Table(
                [[Paragraph(f"<b>{v}</b>", sn)],
                 [Paragraph(k, sl)]],
                colWidths=[cw])
            inner.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), soft),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 8)]))
            row.append(inner)
        t = Table([row], colWidths=[cw] * n)
        t.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
        return t

    def _fmt_val(vv, max_len=80):
        """把原始值格式化为适合 PDF 的简短字符串, 避免 Python repr。"""
        if isinstance(vv, (list, tuple)):
            s = ", ".join(str(x) for x in vv)
        elif isinstance(vv, dict):
            s = "; ".join(f"{k}={v}" for k, v in vv.items())
        else:
            s = str(vv)
        return s[:max_len]

    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")
    PW, PH = A4
    LM = RM = 14 * mm
    TM = 16 * mm
    BM = 14 * mm

    def _on_page(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(C_LINE)
        canvas.setLineWidth(0.5)
        canvas.line(LM, BM - 4 * mm, PW - RM, BM - 4 * mm)
        canvas.setFont(FONT, 7.5)
        canvas.setFillColor(C_FAINT)
        canvas.drawString(LM, BM - 8 * mm,
                          f"{report['app']} / {report['version']} · 自动生成诊断报告")
        canvas.drawRightString(PW - RM, BM - 8 * mm, f"第 {doc_.page} 页")
        canvas.restoreState()

    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=LM, rightMargin=RM,
                          topMargin=TM, bottomMargin=BM,
                          title=f"{report['app']} 诊断报告")
    frame = Frame(LM, BM, PW - LM - RM, PH - TM - BM, id="main")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=_on_page)])

    flow = []
    content_w = PW - LM - RM

    sys_i = report["system"]
    health = report["health"]
    counts = report["counts"]
    modules = report["modules"]

    # ── 页眉深带 (含健康分) ──
    score_box = Table(
        [[Paragraph(f"<b>{health['score']}</b>", h_score)],
         [Paragraph(f"{health['grade']} · {health['label']}", h_score_lbl)]],
        colWidths=[36 * mm], rowHeights=[28 * mm, 8 * mm])
    score_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#2563eb")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
        ("VALIGN", (0, 1), (0, 1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8)]))

    header = Table(
        [[Paragraph(f"<b>{report['app']}</b><br/>{report['version']}",
                    h_title),
          score_box],
         [Paragraph(f"<b>网络诊断报告</b><br/>"
                    f"生成时间: {g}<br/>"
                    f"健康分: {health['score']} / 100 ({health['grade']})",
                    h_sub),
          Paragraph("", h_sub)]],
        colWidths=[content_w - 36 * mm, 36 * mm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BAND),
        ("SPAN", (0, 1), (-1, 1)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    flow.append(header)
    flow.append(Spacer(1, 10))

    # ── 待办问题 (按严重度) ──
    todo_issues = []
    for m in modules:
        for issue in m.get("issues", []):
            todo_issues.append({**issue, "_module": m["name"]})
    sev_order = {"异常": 0, "错误": 0, "警告": 1, "信息": 2}
    todo_issues.sort(key=lambda i: sev_order.get(i.get("severity", "信息"), 3))

    if todo_issues:
        flow.append(Paragraph(
            f"<b>需要您关注 ({len(todo_issues)} 项)</b>", sec))
        todo_rows = []
        todo_rows.append([
            Paragraph("<b>严重度</b>", th),
            Paragraph("<b>问题</b>", th),
            Paragraph("<b>建议</b>", th),
        ])
        for issue in todo_issues[:10]:
            sev = issue.get("severity", "信息")
            sev_color = {"异常": "#dc2626", "错误": "#7f1d1d",
                         "警告": "#ea580c", "信息": "#64748b"}.get(sev, "#64748b")
            todo_rows.append([
                Paragraph(f"<b><font color='{sev_color}'>{sev}</font></b>", cell),
                Paragraph(f"<b>{issue.get('text', '')}</b>", cell),
                Paragraph(issue.get("action", "—") or "—", cell),
            ])
        todo_t = Table(todo_rows,
                       colWidths=[16 * mm, (content_w - 16 * mm) * 0.45,
                                  (content_w - 16 * mm) * 0.55],
                       repeatRows=1)
        todo_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_PRI_SOFT),
            ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(todo_t)
        flow.append(Spacer(1, 6))
    else:
        flow.append(Paragraph("<b>所有检测通过</b>", sec))
        flow.append(Paragraph(
            "<font color='#16a34a'>网络状态良好，所有 18 项检测均正常，无需特别处理。</font>",
            mod_sub))
        flow.append(Spacer(1, 6))

    # ── 主机信息 + 状态统计卡 ──
    flow.append(Paragraph("<b>主机信息</b>", sec))
    sys_pairs = [
        ("本机 IP", sys_i.get("local_ip", "未知")),
        ("默认网关", sys_i.get("gateway", "未知")),
        ("DNS", sys_i.get("dns", "未知")),
        ("公网 IP", sys_i.get("public_ip", "未知")),
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

    # 2 列布局, 每行 2 项
    rows = []
    for i in range(0, len(sys_pairs), 2):
        row = [Paragraph("<b>" + sys_pairs[i][0] + "</b>", lbl),
               Paragraph(sys_pairs[i][1], val)]
        if i + 1 < len(sys_pairs):
            row += [Paragraph("<b>" + sys_pairs[i + 1][0] + "</b>", lbl),
                    Paragraph(sys_pairs[i + 1][1], val)]
        else:
            row += [Paragraph("", lbl), Paragraph("", val)]
        rows.append(row)
    if not rows:
        rows = [[Paragraph("(无)", val), Paragraph("", val),
                 Paragraph("", lbl), Paragraph("", val)]]
    st = Table(rows, colWidths=[22 * mm, (content_w - 44 * mm) / 2,
                                 22 * mm, (content_w - 44 * mm) / 2])
    st.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("BACKGROUND", (0, 0), (-1, -1), C_CARD),
        ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, C_LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6)]))
    flow.append(st)
    flow.append(Spacer(1, 6))

    flow.append(Paragraph("<b>检测汇总</b>", sec))
    flow.append(_stat_cards(counts))
    flow.append(Spacer(1, 6))
    total = len(modules)
    ok_n = counts.get("完成", 0)
    flow.append(Paragraph(
        f"共 {total} 项检测, 其中 <b>{ok_n}</b> 项正常、"
        f"<b>{counts.get('警告',0)}</b> 项警告、"
        f"<b>{counts.get('异常',0)+counts.get('错误',0)}</b> 项异常。"
        f" {health['verdict']}。",
        mod_sub))

    # ── 详细结果 (每模块一张卡片) ──
    flow.append(Paragraph("<b>详细结果</b>", sec))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=C_LINE,
                           spaceBefore=0, spaceAfter=6))

    for m in modules:
        status = m["status"]
        c = SC.get(status, C_IDLE)
        verdict = m.get("verdict", "")

        # ── 标题条 (仅 1 行的小块, KeepTogether 不会造成大段空白) ──
        dot = Table([[""]], colWidths=[3 * mm], rowHeights=[3 * mm])
        dot.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
        heading = Table(
            [[dot, Paragraph(f"<b>{m['name']}</b>", mod_title),
              _badge(status)]],
            colWidths=[5 * mm, content_w - 29 * mm, 24 * mm])
        heading.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LINEBEFORE", (0, 0), (0, -1), 3, c)]))
        # 接近页底时先分页, 避免标题孤行; 不会因整块 KeepTogether 留大空白
        flow.append(CondPageBreak(22 * mm))
        flow.append(KeepTogether(heading))
        flow.append(Spacer(1, 3))

        # 结论 (流式段落, 可跨页)
        if verdict:
            flow.append(Paragraph(
                f"<font color='{SC_HEX.get(status, '#1e40af')}'>"
                f"<b>结论</b></font>　{_html_esc(verdict)}", concl))
            flow.append(Spacer(1, 3))

        # 模块说明 (装维视角: 这是在测什么、结果怎么看)
        explain = MODULE_EXPLAINS.get(m.get("key", ""), "")
        if explain:
            flow.append(Paragraph(
                f"<font size=7.5 color='#64748b'>📖 {_html_esc(explain)}</font>", concl))
            flow.append(Spacer(1, 3))

        # 关键指标 (流式 2 列键值表, 行可拆分, 不整体 KeepTogether)
        metrics = m.get("key_metrics", [])
        if metrics:
            mrows = []
            for me in metrics:
                # 与 HTML 口径一致: 空值指标 (—/N/A/无) 不占行
                if str(me.get("value", "")).strip() in ("—", "N/A", "无", ""):
                    continue
                lvl = me.get("level", "ok")
                vstyle = metric_val_map.get(lvl, metric_val_ok)
                hint = me.get("hint", "")
                vtext = me.get("value", "")
                # 与 HTML 口径一致: 正常指标不加说明文字, 保持卡片清爽
                if hint and lvl in ("warn", "err"):
                    vtext += (f"  <font size=7 color='#b45309'>"
                              f"{_html_esc(hint)}</font>")
                mrows.append([
                    Paragraph(_html_esc(me.get("label", "")), metric_lbl),
                    Paragraph(vtext, vstyle)])
            mt = Table(mrows, colWidths=[52 * mm, content_w - 52 * mm])
            mt.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
            flow.append(mt)
            flow.append(Spacer(1, 4))

        # 问题/建议 (流式段落)
        issues = m.get("issues", [])
        for issue in issues:
            sev = issue.get("severity", "信息")
            text = issue.get("text", "")
            impact = issue.get("impact", "")
            action = issue.get("action", "")
            sev_color = {"异常": "#dc2626", "错误": "#7f1d1d",
                         "警告": "#ea580c", "信息": "#64748b"}.get(sev, "#64748b")
            bullet = Table([[""]], colWidths=[2.5 * mm], rowHeights=[2.5 * mm])
            bullet.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(sev_color)),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
            flow.append(Table(
                [[bullet, Paragraph(
                    f"<b><font color='{sev_color}'>[{sev}]</font></b> "
                    f"{_html_esc(text)}",
                    warn_style if sev == "警告" else err_style)]],
                colWidths=[5 * mm, content_w - 5 * mm]))
            if impact:
                flow.append(Paragraph(
                    f"<b>影响:</b> {_html_esc(impact)}", cell))
            if action:
                flow.append(Paragraph(
                    f"<b><font color='#b45309'>建议:</font></b> "
                    f"{_html_esc(action)}", action_style))
            flow.append(Spacer(1, 2))

        # 技术细节 (简化摘要, 表格可拆分跨页; 完整数据见 JSON)
        if m.get("has_tech_details"):
            pres = MODULE_PRESENTATION.get(m["key"], {})
            tech_keys = pres.get("tech_keys", [])
            raw = m.get("raw", {})
            tech_elems = []
            for k in tech_keys:
                v = raw.get(k)
                if v is None:
                    continue
                if isinstance(v, (list, dict, tuple)) and not v:
                    continue
                label = HEADER_MAP.get(k, k)
                tech_elems.append(Paragraph(
                    f"<b>{_html_esc(label)}</b>", detail_sec))

                if isinstance(v, list) and v:
                    if all(isinstance(x, dict) for x in v):
                        rt = _record_table(v)
                    else:
                        rt = None
                    if rt:
                        headers, rows = rt
                        show = rows[:5]
                        cell_data = [[Paragraph(_html_esc(h), th)
                                      for h in headers]]
                        for r in show:
                            cell_data.append([
                                Paragraph(_html_esc(str(c)[:60]), tech_cell)
                                for c in r])
                        n_cols = len(headers)
                        cw = (content_w - 12) / max(n_cols, 1)
                        rtbl = Table(cell_data,
                                     colWidths=[cw] * n_cols,
                                     repeatRows=1)
                        rtbl.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), C_PRI_SOFT),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("BOX", (0, 0), (-1, -1), 0.4, C_LINE),
                            ("INNERGRID", (0, 0), (-1, -1), 0.3, C_LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ]))
                        tech_elems.append(Spacer(1, 2))
                        tech_elems.append(rtbl)
                        if len(rows) > 5:
                            tech_elems.append(Paragraph(
                                f"<font color='#94a3b8'>"
                                f"⋯ 还有 {len(rows) - 5} 行, 详见 JSON 报告</font>",
                                detail_cap))
                        continue
                    s = ", ".join(str(x) for x in v)
                    tech_elems.append(Paragraph(_html_esc(s[:150]), tech_cell))
                    continue

                if isinstance(v, dict):
                    pairs = []
                    for kk, vv in list(v.items())[:6]:
                        if vv is None or vv == "":
                            continue
                        pairs.append((HEADER_MAP.get(kk, kk),
                                      _fmt_val(vv, 80)))
                    if pairs:
                        p_rows = []
                        for lbl, val in pairs:
                            p_rows.append([
                                Paragraph(f"<b>{_html_esc(lbl)}</b>",
                                          metric_lbl),
                                Paragraph(_html_esc(val), tech_cell)])
                        ptbl = Table(p_rows,
                                     colWidths=[40 * mm,
                                                content_w - 40 * mm])
                        ptbl.setStyle(TableStyle([
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 1),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
                        tech_elems.append(Spacer(1, 2))
                        tech_elems.append(ptbl)
                else:
                    tech_elems.append(Paragraph(
                        _html_esc(str(v)[:150]), tech_cell))

            if tech_elems:
                flow.append(Spacer(1, 3))
                flow.append(Paragraph(
                    "<font color='#94a3b8'>"
                    "技术细节（完整数据见 .json 报告）</font>", detail_cap))
                for elem in tech_elems:
                    flow.append(elem)

        flow.append(Spacer(1, 8))
        flow.append(HRFlowable(width="100%", thickness=0.4, color=C_LINE,
                               spaceBefore=1, spaceAfter=6))

    doc.build(flow)
    return True


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

    结构 (build_report 双视图):
      - meta: 应用信息 + 生成时间 + 主机信息 + 模块运行列表
      - health: 健康评分 (score, grade, label, verdict) + counts
      - modules: 客户视图 (verdict + key_metrics + issues)
      - tech.raw_results: 每个模块的原始 result 字典 (含 30 个 RTT 全序列等)
      - tech.thresholds: 阈值定义 (为啥这个值是"异常"的依据)
      - tech.module_presentation: 每个模块的客户视图配置 key
    """
    if not report:
        return "{}"
    out = {
        "meta": {
            "app": report["app"],
            "version": report["version"],
            "generated_at": report["generated_at"],
            "host": report["system"],
        },
        "health": report["health"],
        "counts": report["counts"],
        "summary": report["summary"],
        "modules": report["modules"],
        "tech": report["tech"],
    }
    return json.dumps(out, ensure_ascii=False, indent=indent, default=_json_default)


# 老的 render_report_text 保留, 但 export_report 默认不再导出
# (客户报告走 HTML/PDF/JSON, TXT 是 legacy 模式; 仍可手工调用)
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


def export_report(path, auto_install=False, pip_mirror=None):
    """按扩展名导出客户版报告: .html / .pdf / .json。

    客户版设计:
      - .html → 客户版 HTML (健康分 + 问题清单 + 关键指标 + 折叠技术细节)
      - .pdf  → 客户版 PDF (浅色主题, 适合打印/归档)
      - .json → 技术员/脚本用 (含 raw 原始数据 + 阈值定义)

    老的 .txt 报告 (拍平所有数据) 已废弃, 导出 .txt 现在会返回错误提示。
    如需旧格式, 请手动调用 render_report_text()。

    auto_install: True 时允许 PDF 导出时自动 pip install reportlab
    pip_mirror: 显式指定 pip 镜像 (CLI --pip-mirror)
    """
    path = _normalize_report_path(path)
    report = build_report()
    if not report:
        return "尚无诊断数据，无法生成报告（请先运行诊断）"
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".pdf":
            ok = render_report_pdf(report, path, auto_install=auto_install,
                                   pip_mirror=pip_mirror)
            if ok:
                return None
            # 降级: 自动导出同名 HTML, 保证用户总能拿到可读报告
            html_path = os.path.splitext(path)[0] + ".html"
            try:
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(render_report_html_customer(report))
                return ("PDF 导出失败（reportlab 未就绪），已自动降级导出 HTML: "
                        + os.path.abspath(html_path))
            except Exception as e2:
                return f"PDF 导出失败: {e2}"
        elif ext in (".html", ".htm"):
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_report_html_customer(report))
            return None
        elif ext == ".json":
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_report_json(report))
            return None
        elif ext == ".txt":
            return ("TXT 客户版未提供, 改用 --export report.html / .pdf / .json。"
                    "如需旧拍平格式, 可手动调用 render_report_text()。")
        else:
            return f"不支持的扩展名: {ext} (支持: .html / .pdf / .json)"
    except Exception as e:
        return f"导出失败: {e}"


def prompt_export_report(auto_install=False, pip_mirror=None):
    """交互菜单跑完后, 询问是否将本次诊断导出为报告文件。

    auto_install: True 时 PDF 导出允许自动安装 reportlab
    (例如 CLI 加了 --install, 在交互菜单中也保持一致行为)。
    pip_mirror: 透传给 export_report。
    """
    if not LAST_RUN:
        return
    try:
        ans = input(_c("  是否生成诊断报告? [y/N] ", C_GREEN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if ans not in ("y", "yes"):
        return
    try:
        fmt = input(_c("  选择格式 (1=TXT  2=HTML  3=PDF, 默认3): ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        fmt = "3"
    ext = {"1": ".txt", "2": ".html", "3": ".pdf"}.get(fmt, ".pdf")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"netdiag_report_{ts}{ext}"
    try:
        name = input(_c(f"  保存文件名 [{default_name}]: ", C_GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        name = ""
    if not name:
        name = default_name
    if not os.path.splitext(name)[1]:
        name += ext
    err = export_report(name, auto_install=auto_install, pip_mirror=pip_mirror)
    if err:
        print(_c(f"  ✗ {err}", C_RED))
    else:
        print(_c(f"  ✓ 报告已导出: {os.path.abspath(_normalize_report_path(name))}", C_GREEN))


def parse_choice(choice):
    """解析交互菜单输入 -> keys 列表; 无效返回 None。
    支持: 数字 (空格分隔多选)、0/all/* (全部)、分类字母 a/b/c、
    模块 key、模块中文名。
    严格模式: 任一 token 非法即整体拒绝。
    """
    choice = (choice or "").strip()
    if choice == "":
        return None
    if choice.lower() in ("0", "all", "*"):
        return [k for k, _, _ in MODULE_REGISTRY]
    return _parse_keys(choice.split(), strict=True)


def interactive_menu(install=False, pip_mirror=None):
    """交互式数字选择菜单 (cmd 窗口)。

    install: 是否允许在交互过程中自动安装缺失依赖
             (与 CLI --install 联动, 让 PDF 导出等行为可预测)。
    pip_mirror: 透传给 ensure_scapy / ensure_reportlab。

    并发策略:
      - 选 0 / 选多个模块 -> 默认并发 (跟 CLI `all --parallel` 对齐,
        选全部时绝大多数用户想要快而不是看实时进度)
      - 选单模块 -> 走顺序, 让 TTY 实时进度行 (\\r\\033[K 刷新) 正常显示
      - run_diagnostics 内部 `parallel and len(keys) > 1` 会自动归一化
    """
    while True:
        # 清屏: 用 ANSI 转义 (VT 已在 _cli_enable_vt 启用) 替代 os.system('cls'),
        # 避免 cmd.exe 解析 + 子进程阻塞。VT 未启用时退回到 subprocess 直调 cls。
        if not _clear_screen():
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
        bar = "=" * 60
        print(_c(bar, C_BLUE))
        print(_c(f"  {APP_NAME} v{APP_VERSION}    命令行网络诊断", C_BOLD))
        print(_c(bar, C_BLUE))
        print(_c("  请选择要执行的诊断 (输入数字 / 分类 a,b,c / 模块 key):", C_WHITE))
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
        print(f"    {_c(' 0', C_CYAN)}. 运行全部诊断 {_c('(默认并发)', C_GRAY)}")
        print(f"    {_c(' m', C_CYAN)}. 盯障模式 {_c('(长时间监测, 找偶发掉线)', C_GRAY)}")
        print(f"    {_c(' e', C_CYAN)}. 导出上次诊断报告")
        print(f"    {_c(' q', C_CYAN)}. 退出")
        print(_c("  快捷: a/b/c=按分类运行; all/0/*=全部; m=盯障; e=导出报告。", C_GRAY))
        print(_c("-" * 60, C_GRAY))
        try:
            choice = input(_c("  输入 > ", C_GREEN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice.lower() in ("q", "quit", "exit"):
            break
        # m / monitor: 盯障模式 (独立运行模式, 不进模块注册表)
        if choice.lower() in ("m", "monitor", "盯障"):
            sec = 600
            if sys.stdout.isatty():
                try:
                    raw = input(_c("  监测时长(秒, 回车=600, 范围 30-86400): ",
                                   C_GREEN)).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    continue
                if raw:
                    try:
                        sec = int(raw)
                    except ValueError:
                        print(_c("  无效时长, 使用默认 600 秒。", C_YELLOW))
                        sec = 600
            run_monitor_mode(sec)
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
                prompt_export_report(auto_install=install, pip_mirror=pip_mirror)
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
        # 端口探测: 不管是单选 port 还是 0/all, 跑之前都要求用户输入目标
        # (用户偏好: 端口探测必须有显式目标, 不再有隐式默认)
        if "port" in keys and not PORT_PROBE_CONFIG.get("targets"):
            prompted = _prompt_for_port_targets()
            if prompted is None:
                # 用户取消: 跳过 port, 跑其余模块
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
        # iperf3 模块: 菜单模式运行 iperf3 时询问服务器 (默认不测, 缺服务器会明确报错)
        # 已被 CLI --iperf3-server 预设过就不重复问; 非 TTY 不问 (否则会吃掉管道输入)
        if ("iperf3" in keys and not SPEEDTEST_CONFIG.get("iperf3_server")
                and sys.stdout.isatty()):
            iperf3 = _prompt_for_iperf3()
            if iperf3 is not None:
                host, port = iperf3
                SPEEDTEST_CONFIG["iperf3_server"] = host
                SPEEDTEST_CONFIG["iperf3_port"] = port
                print(_c(f"  → iperf3 server: {host}:{port}", C_GRAY))
                # 提前确保 iperf3.exe 就位 (避免测速进度被 input("未找到 iperf3.exe") 打断)
                Iperf3Tester()._find_iperf3(auto_download=True)
            else:
                print(_c("  → 未提供 iperf3 服务器, 该模块运行时会提示缺少服务器", C_GRAY))
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
                prompt_export_report(auto_install=install, pip_mirror=pip_mirror)
        try:
            input(_c("\n  按 Enter 返回菜单...", C_GRAY))
        except (EOFError, KeyboardInterrupt):
            break


def main():
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
    parser.add_argument("--install", action="store_true",
                        help="自动安装缺失依赖 (scapy/Npcap), 无需交互确认")
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
                        help="诊断后将报告导出到文件 (支持 .txt / .html / .pdf); "
                             "多个目标用逗号分隔可一次导出多种格式, 例: report.pdf,report.html,report.txt")
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
                             "质量口径): 抖动 >30ms 或丢包 >1% 给出告警; 默认 TCP 测吞吐")
    parser.add_argument("--speedtest-net", action="store_true",
                        help="启用 Speedtest.net 测速 (默认关闭: 国内网络下常选中"
                             "海外服务器, 结果严重偏低, 仅作参考)")
    parser.add_argument("--speedtest-node", metavar="ID|HOST:PORT",
                        help="指定上行测速服务器 (可选): speedtest 服务器 ID 或 "
                             "host:port (如 3633 或 112.25.80.50:8080); "
                             "默认自动选择延迟最低的国内运营商节点")
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
    args = parser.parse_args()

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
    # 盯障模式: 独立顶层运行模式 (与模块诊断互斥)
    if args.monitor:
        run_monitor_mode(args.monitor, ext_target=args.monitor_target)
        return
    if args.modules:
        is_all_only = (args.modules == ["all"])
        if is_all_only:
            keys = [k for k, _, _ in MODULE_REGISTRY]
        else:
            keys = parse_module_names(args.modules)
        if not keys:
            print("可用模块: " + ", ".join(k for k, _, _ in MODULE_REGISTRY))
            return
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
                sys.exit(2)
        run_diagnostics(keys, verbose=args.verbose, as_json=args.json,
                        no_color=args.no_color, install=args.install,
                        parallel=args.parallel, max_workers=args.max_workers,
                        pip_mirror=args.pip_mirror)
        if args.export:
            targets = [t.strip() for t in args.export.split(",") if t.strip()]
            if not targets:
                targets = [args.export]
            for t in targets:
                err = export_report(t, auto_install=args.install,
                                    pip_mirror=args.pip_mirror)
                if err:
                    print(_c(f"  ✗ {err}", C_RED))
                else:
                    print(_c(f"  ✓ 报告已导出: {os.path.abspath(_normalize_report_path(t))}", C_GREEN))
        return
    # 无参数 -> 进入交互式菜单
    interactive_menu(install=args.install, pip_mirror=args.pip_mirror)


if __name__ == "__main__":
    main()
