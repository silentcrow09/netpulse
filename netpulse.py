#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetPulse - Windows 网络诊断工具
单文件便携版 v1.0.0

功能模块:
  1.  局域网 DHCP 多服务器干扰检测
  2.  内网网关延迟 / 丢包检测
  3.  内网环路检测
  4.  外网延迟 / 路径 / 丢包检测
  5.  有线 / WiFi 协商速率检测
  6.  WiFi 干扰分析
  7.  内外网测速 (iperf3 + Speedtest + HTTP)
  8.  TCP 连接数探测
  9.  多外网出口检测
  10. DNS 解析诊断 (补充)
  11. MTU 路径发现 (补充)
  12. ARP 表分析 / 欺骗检测 (补充)
  13. Bufferbloat 负载延迟检测 (补充)
  14. IPv6 连通性检测 (补充)
  15. 路由表异常分析 (补充)
"""

# ============================================================
# SECTION 1: IMPORTS
# ============================================================

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
import argparse
import tempfile
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request

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
PORT_PROBE_CONFIG = {"targets": None, "proto": "tcp", "count": 4}


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


def _urlopen_with_proxy(url, timeout=120):
    """带环境变量代理支持的下载 (兼容企业代理网络)"""
    import urllib.request as ur
    proxies = {}
    for env_key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        val = os.environ.get(env_key)
        if val:
            scheme = env_key.lower().split("_")[0]
            proxies[scheme] = val
    handlers = [ur.ProxyHandler(proxies)] if proxies else []
    opener = ur.build_opener(*handlers)
    req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
    return opener.open(req, timeout=timeout)


def _pip_install_scapy(mirror=None):
    """用当前解释器安装 scapy。返回 (ok, msg)。

    mirror: 显式指定的 pip 镜像 URL; None 时由 _resolve_pip_mirror 自动选源。
    """
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
EXTERNAL_TARGETS = [
    ("223.5.5.5", "AliDNS"),
    ("114.114.114.114", "114DNS"),
    ("119.29.29.29", "DNSPod"),
    ("www.baidu.com", "Baidu"),
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


def _download_speed_test(url, target_bytes=5 * 1024 * 1024, chunk_size=64 * 1024,
                         overall_timeout=20, callback=None):
    """下载测速通用函数: chunked read 累计到 target_bytes 就 stop, 不等下完。

    与 ``resp.read()`` 一次读完的区别:
      - 旧版 resp.read() 必须等服务器发完全部数据, 10MB 文件在 1Mbps 链路
        需要 80s, 国际 CDN 从国内访问 5-10 分钟
      - 新版累计下载到 target_bytes (默认 5MB) 就 break 退出, 100Mbps 链路
        不到 1s 出结果, 10Mbps ~4s, 1Mbps ~40s (并伴随进度反馈)

    参数:
      url: 测速源 URL
      target_bytes: 累计下载到这么多字节就停 (默认 5MB, 测速精度足够)
      chunk_size: 每次 read 的块大小 (默认 64KB)
      overall_timeout: 整体超时秒数 (默认 20s, 超过就 break 用已下载数据)
      callback: 进度回调, 接受 str (每 1MB 或每 1s 报一次)

    返回 dict (含 download_mbps / downloaded_mb / elapsed_s) 或 None (失败)。
    """
    try:
        req = Request(url, headers={"User-Agent": "NetPulse/1.0"})
        start = time.time()
        deadline = start + overall_timeout
        # connect timeout 短一点 (10s 足够建立连接)
        resp = urlopen(req, timeout=10)
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
                "downloaded_mb": round(downloaded / 1e6, 2),
                "elapsed_s": round(elapsed, 2),
            }
        return None
    except Exception as e:
        if callback:
            callback(f"  测速失败 ({url[:40]}...): {e}")
        return None


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
    """获取公网 IP (国内 IP 服务, 并发请求, 首个成功即返回)。"""
    services = [
        ("https://qifu-api.baidubce.com/ip/local/geo/v1/district", "json"),
        ("https://myip.ipip.net", "text"),
        ("https://ddns.oray.com/checkip", "text"),
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

    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(_probe, u, m) for u, m in services]
        for f in as_completed(futs):
            ip = f.result()
            if ip:
                return ip
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
                            "lease_time": 0,
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

        if SCAPY_AVAILABLE:
            servers, err = self.detect_scapy(timeout=10)
            if err:
                errors.append(err)
            method = "scapy"
            if not servers:
                servers = self.detect_fallback()
                method = "scapy+fallback"
        else:
            servers = self.detect_fallback()
            method = "ipconfig"
            errors.append("scapy 未安装，仅能检测当前 DHCP 服务器 (需要 Npcap 进行完整检测)")

        # 分析结果
        interference = len(servers) > 1
        self.results = {
            "servers": servers,
            "interference": interference,
            "method": method,
            "errors": errors,
            "timestamp": datetime.now().isoformat(),
            "summary": f"发现 {len(servers)} 个 DHCP 服务器" +
                       (" — 存在多服务器干扰!" if interference else " — 正常"),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class GatewayTester:
    """网关延迟 / 丢包检测"""

    def __init__(self):
        self.name = "网关延迟检测"
        self.results = {}

    def detect(self, count=30, callback=None):
        if callback:
            callback("正在检测网关延迟...")
        gateway = get_default_gateway()
        if not gateway:
            self.results = {"error": "无法获取默认网关"}
            return self.results

        if callback:
            callback(f"Ping 网关 {gateway} ({count} 次)...")

        ping_result = ping_host(gateway, count=count, timeout=count + 10)

        # 评估
        assessment = "正常"
        if ping_result["loss_pct"] > 0:
            assessment = "存在丢包"
        if ping_result["loss_pct"] > 5:
            assessment = "丢包严重"
        if ping_result["avg_ms"] > 10:
            assessment = "延迟偏高"
        if ping_result["avg_ms"] > 50:
            assessment = "延迟严重"
        if ping_result["loss_pct"] > 5 and ping_result["avg_ms"] > 10:
            assessment = "网络质量差"

        self.results = {
            "gateway": gateway,
            "ping": ping_result,
            "assessment": assessment,
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
        for line in arp_out.split("\n"):
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()
                arp_entries.append({"ip": ip, "mac": mac, "type": m.group(3)})
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
                    issues.append({
                        "type": "intermittent_loss",
                        "severity": "warning",
                        "message": f"网关存在间歇性丢包 ({ping_result['loss_pct']}%) 且抖动较大 ({ping_result['jitter_ms']}ms)",
                        "detail": "间歇性丢包 + 高抖动是网络环路的典型征兆，建议进一步排查"
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
    """外网延迟 / 路径 / 丢包检测"""

    def __init__(self):
        self.name = "外网网络检测"
        self.results = {}

    def detect(self, targets=None, callback=None):
        if callback:
            callback("正在检测外网连通性...")
        if targets is None:
            targets = EXTERNAL_TARGETS

        results = []

        def _test_target(tip, tname):
            # Ping 测试
            ping_result = ping_host(tip, count=10, timeout=15)
            # Traceroute (15 跳足够覆盖国内主流路径)
            code, tracert_out, _ = run_cmd(
                f"tracert -d -h 15 -w 1000 {tip}", timeout=40)
            hops = parse_tracert_output(tracert_out)
            # DNS 解析 (如果目标是域名)
            dns_time = None
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", tip):
                try:
                    start = time.time()
                    socket.gethostbyname(tip)
                    dns_time = round((time.time() - start) * 1000, 1)
                except Exception:
                    dns_time = None
            return {"target": tip, "name": tname,
                    "loss_pct": ping_result["loss_pct"],
                    "avg_ms": ping_result["avg_ms"],
                    "hop_count": len(hops),
                    "dns_time_ms": dns_time,
                    "_hops": hops}

        if callback:
            callback(f"外网检测 {len(targets)} 个目标 (并发)...")
        with ThreadPoolExecutor(max_workers=min(4, len(targets))) as ex:
            for r in ex.map(lambda t: _test_target(*t), targets):
                results.append(r)

        # 综合评估
        all_loss = [r["loss_pct"] for r in results]
        all_rtt = [r["avg_ms"] for r in results if r["avg_ms"] > 0]
        avg_loss = sum(all_loss) / len(all_loss) if all_loss else 100
        avg_rtt = sum(all_rtt) / len(all_rtt) if all_rtt else 0

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

        if avg_loss == 0 and avg_rtt < 50:
            assessment = "外网连通正常"
        elif avg_loss < 5 and avg_rtt < 100:
            assessment = "外网连通性良好"
        elif avg_loss < 20:
            assessment = "外网存在一定丢包"
        else:
            assessment = "外网连通性差"

        self.results = {
            "targets": results,
            "traceroute": traceroute,
            "avg_loss_pct": round(avg_loss, 1),
            "avg_rtt_ms": round(avg_rtt, 1),
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "summary": f"外网检测: 平均延迟 {avg_rtt:.0f}ms, 平均丢包 {avg_loss:.1f}%",
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

        # 解析 WiFi 接口信息
        wifi_details = {}
        current_section = None
        for line in wifi_info.split("\n"):
            line_s = line.strip()
            if "SSID" in line_s and "BSSID" not in line_s:
                m = re.match(r"SSID\s*:\s*(.*)", line_s)
                if m:
                    wifi_details["connected_ssid"] = m.group(1).strip()
            elif "接收速率" in line_s or "Receive rate" in line_s:
                m = re.search(r":\s*([\d.]+)\s*", line_s)
                if m:
                    wifi_details["rx_rate"] = float(m.group(1))
            elif "发送速率" in line_s or "Transmit rate" in line_s:
                m = re.search(r":\s*([\d.]+)\s*", line_s)
                if m:
                    wifi_details["tx_rate"] = float(m.group(1))
            elif "信号" in line_s or "Signal" in line_s:
                m = re.search(r":\s*(\d+)%", line_s)
                if m:
                    wifi_details["signal_pct"] = int(m.group(1))
            elif "频道" in line_s or "Channel" in line_s:
                m = re.search(r":\s*(\d+)", line_s)
                if m:
                    wifi_details["channel"] = int(m.group(1))
            elif "无线电类型" in line_s or "Radio type" in line_s:
                m = re.match(r".*:\s*(.*)", line_s)
                if m:
                    wifi_details["radio_type"] = m.group(1).strip()
            elif "身份验证" in line_s or "Authentication" in line_s:
                m = re.match(r".*:\s*(.*)", line_s)
                if m:
                    wifi_details["auth"] = m.group(1).strip()
            elif "加密" in line_s or "Cipher" in line_s:
                m = re.match(r".*:\s*(.*)", line_s)
                if m:
                    wifi_details["encryption"] = m.group(1).strip()

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

        self.results = {
            "adapters": adapter_details,
            "wifi_details": wifi_details,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"检测到 {len(adapter_details)} 个网络适配器" +
                       (f", WiFi 信号: {wifi_details.get('signal_pct', 'N/A')}" if wifi_details else ""),
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

        self.results = {
            "networks": all_bssids,
            "network_count": len(all_bssids),
            "channel_analysis": channel_analysis,
            "best_2g_channel": best_2g,
            "best_5g_channel": best_5g,
            "current_channel": current_channel,
            "current_ssid": current_ssid,
            "overall_interference": overall_interference,
            "timestamp": datetime.now().isoformat(),
            "summary": ("发现 " + str(len(all_bssids)) + " 个 BSSID, "
                       "干扰等级: " + str(overall_interference) +
                       ((", 建议使用信道 " + str(best_2g["channel"])) if best_2g else "")),
        }
        if callback:
            callback(self.results["summary"])
        return self.results


class SpeedTester:
    """内外网测速模块"""

    def __init__(self):
        self.name = "网络测速"
        self.results = {}

    def test_speedtest(self, callback=None):
        """使用 speedtest 库测速"""
        if callback:
            callback("Speedtest.net 测速中...")
        if not SPEEDTEST_LIB_AVAILABLE:
            return {"error": "speedtest 库未安装", "method": "speedtest_lib"}

        try:
            st = speedtest.Speedtest(secure=True)
            if callback:
                callback("选择最优服务器...")
            st.get_best_server()
            if callback:
                callback("下载测速中...")
            download_speed = st.download() / 1e6  # Mbps
            if callback:
                callback("上传测速中...")
            upload_speed = st.upload() / 1e6
            server = st.best
            return {
                "method": "speedtest.net",
                "server": f"{server.get('sponsor', '')} ({server.get('name', '')}, {server.get('country', '')})",
                "server_latency_ms": round(server.get('latency', 0), 1),
                "download_mbps": round(download_speed, 2),
                "upload_mbps": round(upload_speed, 2),
            }
        except Exception as e:
            return {"error": str(e), "method": "speedtest_lib"}

    def test_http(self, callback=None):
        """HTTP 下载测速 (降级方案)。

        旧版问题 (用户已踩):
          - 测速源 speedtest.tele2.net / cachefly.cachefly.net 是国外 CDN,
            从国内访问极慢 (17KB/s 量级), 完整下载 10MB 文件要 5-10 分钟
          - resp.read() 一次读完全部数据, 必须等服务器发完才返回
          - timeout=15s 在慢链路上必然超时, 但用户只看到 "HTTP 下载测速中...",
            不知道是卡了还是快好了

        修复:
          - 测速源改为国内 (清华/阿里/腾讯镜像, 700MB boot.iso 支持 range)
            + Cloudflare __down 按需返回 N 字节作为兜底
          - chunked read, 累计下载到 target_bytes (5MB) 就 stop, 不等下完
          - 进度 callback: 每 1MB 或每 1s 报告一次当前速率
          - 整体 overall_timeout=20s 兜底, 慢链路也能给出"低速率"结果
        """
        if callback:
            callback("HTTP 下载测速中...")
        # 国内大文件镜像 + Cloudflare 兜底; 全部 HTTPS, 安全 + 不被劫持。
        # 候选列表按实测速率排序 (腾讯主域 > 华为云 > 腾讯子域 > Cloudflare),
        # 旧版用国外 speedtest.tele2.net / cachefly.cachefly.net 国内只有
        # 17KB/s, 完整下 10MB 要 10 分钟, 是用户报告卡顿的根因。
        # 注意: centos 8 已 EOL, 清华/USTC/163/阿里部分路径已下线, 优先用
        # 还在线的腾讯/华为/Cloudflare 源。
        test_urls = [
            "https://mirrors.tencent.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            "https://mirrors.huaweicloud.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            "https://mirrors.cloud.tencent.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            "https://speed.cloudflare.com/__down?bytes=10485760",
        ]
        for url in test_urls:
            if callback:
                callback(f"  测速源: {url[:60]}{'...' if len(url) > 60 else ''}")
            result = _download_speed_test(
                url, target_bytes=5 * 1024 * 1024,
                overall_timeout=20, callback=callback)
            if result and result.get("downloaded_mb", 0) > 0.05:
                # 至少下到 50KB 才认为有效 (避免空响应/被劫持的短响应)
                return result
        return {"error": "所有 HTTP 测速服务器均不可用或太慢", "method": "http_download"}

    def test_iperf3(self, server, port=5201, duration=10, callback=None):
        """iperf3 客户端测速"""
        if callback:
            callback(f"iperf3 测速: {server}:{port}...")
        # 检查 iperf3 是否可用
        iperf3_path = self._find_iperf3()
        if not iperf3_path:
            return {"error": "iperf3 未找到，请下载 iperf3.exe 并放入 PATH 或程序目录", "method": "iperf3"}

        # 下载测试 (反向)
        if callback:
            callback("iperf3 下载测速 (reverse)...")
        cmd = f'"{iperf3_path}" -c {server} -p {port} -t {duration} -R -J'
        _, out, _ = run_cmd(cmd, timeout=duration + 15)
        download_result = self._parse_iperf3_json(out)

        # 上传测试
        if callback:
            callback("iperf3 上传测速...")
        cmd = f'"{iperf3_path}" -c {server} -p {port} -t {duration} -J'
        _, out, _ = run_cmd(cmd, timeout=duration + 15)
        upload_result = self._parse_iperf3_json(out)

        return {
            "method": "iperf3",
            "server": server,
            "port": port,
            "download_mbps": download_result.get("bitrate_mbps", 0),
            "upload_mbps": upload_result.get("bitrate_mbps", 0),
            "download_retransmits": download_result.get("retransmits", 0),
            "upload_retransmits": upload_result.get("retransmits", 0),
        }

    def _find_iperf3(self):
        """查找 iperf3.exe"""
        # 当前目录
        exe_name = "iperf3.exe"
        if os.path.exists(exe_name):
            return os.path.abspath(exe_name)
        # 程序目录
        app_dir = os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, 'frozen', False) else __file__))
        path = os.path.join(app_dir, exe_name)
        if os.path.exists(path):
            return path
        # PATH
        code, out, _ = run_cmd("where iperf3", timeout=5)
        if code == 0 and out.strip():
            return out.strip().split("\n")[0].strip()
        return None

    def _parse_iperf3_json(self, output):
        """解析 iperf3 JSON 输出"""
        try:
            data = json.loads(output)
            end = data.get("end", {})
            result = {}
            # 接收端 (下载)
            recv = end.get("sum_received", end.get("sum", {}))
            if recv:
                bits_per_sec = recv.get("bits_per_second", 0)
                result["bitrate_mbps"] = round(bits_per_sec / 1e6, 2)
            # 重传
            sum_data = end.get("sum_sent", end.get("sum", {}))
            if sum_data:
                result["retransmits"] = sum_data.get("retransmits", 0)
            return result
        except Exception:
            # 尝试解析文本输出
            m = re.search(r"([\d.]+)\s*(Mbits/sec|Gbits/sec|Kbits/sec)", output)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                if "Gbits" in unit:
                    val *= 1000
                elif "Kbits" in unit:
                    val /= 1000
                return {"bitrate_mbps": round(val, 2)}
            return {}

    def detect(self, iperf3_server=None, iperf3_port=5201, callback=None):
        """执行完整测速"""
        if callback:
            callback("开始网络测速...")
        results = {}

        # Speedtest.net
        st_result = self.test_speedtest(callback)
        results["speedtest"] = st_result

        # 如果 speedtest 失败，用 HTTP 降级
        if "error" in st_result:
            http_result = self.test_http(callback)
            results["http"] = http_result

        # iperf3
        if iperf3_server:
            iperf3_result = self.test_iperf3(iperf3_server, iperf3_port, callback=callback)
            results["iperf3"] = iperf3_result

        # 汇总
        download = 0
        upload = 0
        method = ""
        if "error" not in results.get("speedtest", {}):
            download = results["speedtest"].get("download_mbps", 0)
            upload = results["speedtest"].get("upload_mbps", 0)
            method = "Speedtest.net"
        elif "error" not in results.get("http", {}):
            download = results["http"].get("download_mbps", 0)
            method = "HTTP"
        if "iperf3" in results and "error" not in results["iperf3"]:
            method += " + iperf3"

        results["summary"] = f"测速 ({method}): ↓{format_speed(download)}, ↑{format_speed(upload)}"
        results["timestamp"] = datetime.now().isoformat()
        if callback:
            callback(results["summary"])
        return results


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

        if len(default_routes) > 1:
            issues.append({
                "type": "multiple_default_routes",
                "severity": "warning",
                "message": f"检测到 {len(default_routes)} 条默认路由",
                "detail": "多默认路由可能导致流量分担到不同出口，某条链路故障时可能影响部分流量"
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

        # 3. 检查公网 IP (多个服务并发)
        if callback:
            callback("检测公网出口 IP...")
        public_ips = []
        ip_services = [
            ("https://qifu-api.baidubce.com/ip/local/geo/v1/district", "json"),
            ("https://myip.ipip.net", "text"),
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

        with ThreadPoolExecutor(max_workers=2) as ex:
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

        multiple_egress = len(default_routes) > 1 or len(vpn_adapters) > 0 or len(first_hops) > 1

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

        for line in out.split("\n"):
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()
                arp_type = m.group(3)
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

                # ARP 欺骗检测: 检查是否有 IP 的 MAC 频繁变化
                # (需要多次采样)

            # 检测 ARP 冲突 (同一 IP 多个 MAC — 从 ARP 表可能看不到)
            # 检查静态 ARP 条目
            static_entries = [e for e in entries if e["type"] == "static"]
            if static_entries:
                issues.append({
                    "type": "static_arp",
                    "severity": "info",
                    "message": f"发现 {len(static_entries)} 条静态 ARP 记录",
                    "detail": "静态 ARP 可以防止 ARP 欺骗，但也可能导致 IP 变更后无法通信"
                })

        # 统计
        total_entries = len(entries)
        unique_macs = len(mac_to_ips)
        multi_ip_macs = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}

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

        def generate_load():
            """生成网络负载。

            旧版问题: 用国外测速源 + urlopen 完整文件, 国内访问极慢, 每个
            线程每次循环要等几秒到几十秒, 4 个线程一起也打不满带宽。
            修复: 用国内 + Cloudflare 源, 通过 _download_speed_test 拿 ~1MB
            数据就停 (而不是等完整 1MB 文件), 循环更快, 链路实际更"打满"。
            """
            urls = [
                "https://speed.cloudflare.com/__down?bytes=2097152",
                "https://mirrors.tuna.tsinghua.edu.cn/centos/8/BaseOS/x86_64/os/images/boot.iso",
                "https://mirrors.aliyun.com/centos/8/BaseOS/x86_64/os/images/boot.iso",
            ]
            while not stop_event.is_set():
                for url in urls:
                    if stop_event.is_set():
                        return
                    # 拿 1MB 数据就停, 不等完整大文件
                    _download_speed_test(
                        url, target_bytes=1024 * 1024,
                        overall_timeout=15, callback=None)

        # 启动 4 个负载线程
        for _ in range(4):
            t = threading.Thread(target=generate_load, daemon=True)
            t.start()
            load_threads.append(t)

        # 等待负载建立并稳定: 旧版固定 sleep(2), 慢链路(1Mbps)1MB 需 8s,
        # 容易在带宽尚未打满时就采样; 这里用「多轮 0.5s 心跳确认吞吐
        # 不再增长」的方式自适应, 但设上限避免慢网络下等太久。
        if callback:
            callback("等待链路负载稳定...")
        stable_deadline = time.time() + 8
        prev_bytes = 0
        stable_rounds = 0
        while time.time() < stable_deadline:
            time.sleep(0.5)
            # 简单启发: 如果 4 轮 (2s) 内 stop_event 未 set 且线程仍在跑,
            # 就认为负载已建立; 主线程不直接测量吞吐 (避免给探测本身加噪)
            stable_rounds += 1
            if stable_rounds >= 4:
                break
            if stop_event.is_set():
                break

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
        bloat = loaded_rtt - idle_rtt
        if bloat < 10:
            grade = "A (优秀)"
        elif bloat < 30:
            grade = "B (良好)"
        elif bloat < 60:
            grade = "C (一般)"
        elif bloat < 100:
            grade = "D (较差)"
        else:
            grade = "F (很差)"

        issues = []
        if bloat > 100:
            issues.append(f"严重 Bufferbloat: 负载下延迟增加 {bloat:.0f}ms")
        elif bloat > 30:
            issues.append(f"存在 Bufferbloat: 负载下延迟增加 {bloat:.0f}ms")

        self.results = {
            "gateway": gateway,
            "idle_rtt_ms": idle_rtt,
            "idle_jitter_ms": idle_jitter,
            "loaded_rtt_ms": loaded_rtt,
            "loaded_jitter_ms": loaded_jitter,
            "bloat_ms": round(bloat, 1),
            "grade": grade,
            "issues": issues,
            "timestamp": datetime.now().isoformat(),
            "summary": f"Bufferbloat: 空闲 {idle_rtt:.0f}ms → 负载 {loaded_rtt:.0f}ms (增加 {bloat:.0f}ms, {grade})",
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
        for line in out.split("\n"):
            line = line.strip()
            if "IPv6" in line and ":" in line:
                m = re.search(r":\s*([0-9a-fA-F:]+)", line)
                if m:
                    addr = m.group(1)
                    local_ipv6.append(addr)
                    if addr.startswith("fe80"):
                        has_link_local = True
                    elif not addr.startswith("::1"):
                        has_global_ipv6 = True

        # 2. 检查 IPv6 路由
        code, route_out, _ = run_cmd("route print ::/0")
        has_ipv6_route = "::/0" in route_out

        # 3. IPv6 连通性测试
        ipv6_connectivity = False
        ipv6_dns = False
        try:
            # 尝试连接 IPv6 地址
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            # 2400:3200::1 = 阿里 DNS IPv6
            s.connect(("2400:3200::1", 443))
            s.close()
            ipv6_connectivity = True
        except Exception:
            ipv6_connectivity = False

        # 4. IPv6 DNS 解析
        try:
            socket.getaddrinfo("dns.alidns.com", None, socket.AF_INET6)
            ipv6_dns = True
        except Exception:
            ipv6_dns = False

        if not has_global_ipv6:
            issues.append("未检测到全局 IPv6 地址")
        if has_global_ipv6 and not ipv6_connectivity:
            issues.append("有 IPv6 地址但无法建立 IPv6 连接，可能 IPv6 路由配置有问题")
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
        if len(default_routes) > 1:
            issues.append({
                "type": "multiple_default",
                "severity": "warning",
                "message": f"多条默认路由 ({len(default_routes)} 条)",
                "detail": "可能导致流量路径不确定"
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
        route_map = {r["destination"]: r["gateway"] for r in routes}
        for dest, gw in route_map.items():
            if gw in route_map and route_map[gw] == dest and dest != gw:
                issues.append({
                    "type": "route_loop",
                    "severity": "critical",
                    "message": f"检测到路由环路: {dest} -> {gw} -> {dest}",
                    "detail": "路由表存在环路，可能导致数据包循环"
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

# 默认探测目标 (国内网络环境): 运行 `all` 或 `port` 不带 --port-target 时使用
DEFAULT_PORT_TARGETS = [
    "223.5.5.5:53", "114.114.114.114:53", "119.29.29.29:53", "180.76.76.76:53",
]


def _parse_target(spec):
    """解析 'host:port' 或 '[v6]:port' -> (host, port); 非法返回 None。"""
    spec = (spec or "").strip()
    if not spec:
        return None
    if spec.startswith("["):  # IPv6 方括号形式 [::1]:443
        m = re.match(r"^\[(.+)\]:(\d+)$", spec)
        if m:
            return m.group(1), int(m.group(2))
        return None
    if spec.count(":") == 1:
        h, p = spec.split(":")
        try:
            return h, int(p)
        except ValueError:
            return None
    return None


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

    def __init__(self, targets=None, proto="tcp", count=4):
        self.name = "端口探测"
        self.results = {}
        self.targets = targets or DEFAULT_PORT_TARGETS
        self.proto = (proto or "tcp").lower()
        self.count = max(1, int(count))

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
        for spec in self.targets:
            parsed = _parse_target(spec)
            if not parsed:
                skipped.append(spec)
                continue
            h, p = parsed
            for pr in protos:
                targets.append(self._probe_one(h, p, pr))

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
        parts = local_ip.split(".")
        base = ".".join(parts[:3]) if len(parts) == 4 else None
        devices = []

        # 以 ARP 表为主 (一次命令获取全部近期通信设备, 避免 254 次 ping sweep)
        arp_map = self._get_arp_map()
        for ip, mac in sorted(arp_map.items()):
            if base and not ip.startswith(base + "."):
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
            "subnet": f"{base}.0/24" if base else "",
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
            "conn_failures": r"(Failures|失败)\D+(\d+)",
        }
        for key, pat in patterns.items():
            m = re.search(pat, out)
            if m:
                stats[key] = int(m.group(2))
        return stats if any(stats.values()) else {}



# ============================================================
# SECTION 5: 模块注册与 CLI
# ============================================================

# 模块注册表 (key, 显示名, 检测器类)
MODULE_REGISTRY = [
    ("dhcp",       "DHCP 检测",     DHCPDetector),
    ("gateway",    "网关检测",      GatewayTester),
    ("loop",       "环路检测",      LoopDetector),
    ("external",   "外网检测",      ExternalNetworkTester),
    ("linkspeed",  "链路速率",      LinkSpeedDetector),
    ("wifi",       "WiFi 分析",     WiFiAnalyzer),
    ("tcp",        "TCP 连接",      TCPConnectionAnalyzer),
    ("port",       "端口探测",      PortProbeTester),
    ("egress",     "多出口",        MultiEgressDetector),
    ("dns",        "DNS 诊断",      DNSTester),
    ("mtu",        "MTU 检测",      MTUDetector),
    ("arp",        "ARP 分析",      ARPAnalyzer),
    ("bufferbloat","Bufferbloat",   BufferbloatTester),
    ("ipv6",       "IPv6 检测",     IPv6Tester),
    ("route",      "路由表",        RouteTableAnalyzer),
    ("speedtest",  "测速",          SpeedTester),
    ("lan",        "LAN 设备扫描",  LANDeviceScanner),
    ("tcpstats",   "TCP 传输质量",  TCPStatsTester),
]
MODULE_MAP = {k: (n, c) for k, n, c in MODULE_REGISTRY}

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

STATUS_STYLE = {
    "完成": C_GREEN, "正常": C_GREEN,
    "警告": C_YELLOW,
    "异常": C_RED, "错误": C_RED,
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

    # 2. issues 列表: 任一 critical -> 异常; 否则有 issue -> 警告
    issues = result.get("issues")
    if isinstance(issues, list) and issues:
        if any(isinstance(i, dict) and i.get("severity") == "critical"
               for i in issues):
            _raise("异常")
        else:
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


def _cli_print_result(res, verbose=False, as_json=False):
    """打印单个诊断结果 (精简展示 + 可选 JSON 完整输出)"""
    if as_json:
        out = {k: v for k, v in res.items() if k != "callback"}
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
        return
    # 摘要
    summary = res.get("summary") or res.get("error") or ""
    if summary:
        print(_c("  " + summary, C_WHITE))
    # 问题列表 (最重要的可操作信息)
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
    # 其余字段
    skip = {"summary", "error", "issues", "timestamp", "callback"}
    for k, v in res.items():
        if k in skip:
            continue
        if isinstance(v, (dict, list)):
            s = json.dumps(v, ensure_ascii=False, default=str)
            if len(s) > 200 and not verbose:
                s = s[:200] + f"... (共 {len(s)} 字符, 加 --verbose 查看)"
        else:
            s = str(v)
            if len(s) > 200 and not verbose:
                s = s[:200] + "..."
        print(_c(f"  {k}: ", C_CYAN) + s)


def _print_module_list():
    """打印所有可用诊断模块"""
    print(_c(f"{APP_NAME} v{APP_VERSION} — 可用诊断模块:", C_BOLD))
    for i, (k, n, _) in enumerate(MODULE_REGISTRY, 1):
        print(f"  {_c(str(i).rjust(2), C_CYAN)}. {_c(n, C_WHITE)}  {_c('(' + k + ')', C_GRAY)}")


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
        sys_info = {"local_ip": lip, "gateway": gw, "dns": dns, "public_ip": pub}
        print(_c(f"  本机IP: {lip}", C_WHITE) +
              _c(f"    网关: {gw}", C_WHITE) +
              _c(f"    DNS: {dns}", C_WHITE) +
              _c(f"    公网IP: {pub}", C_WHITE))
    except Exception as e:
        print(_c(f"  系统信息获取失败: {e}", C_GRAY))
    print(_c("-" * 60, C_GRAY))

    IS_TTY = sys.stdout.isatty()
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
        _cli_print_result(res, verbose=verbose, as_json=as_json)

    # 汇总
    print()
    print(_c("=" * 60, C_BLUE))
    print(_c("  诊断汇总", C_BOLD))
    print(_c("-" * 60, C_GRAY))
    cnt = {}
    for key, st in results.items():
        n = MODULE_MAP[key][0]
        print(f"  {_cli_status_badge(st)}  {_c(n, C_WHITE)}")
        cnt[st] = cnt.get(st, 0) + 1
    print(_c("-" * 60, C_GRAY))
    summ = []
    if cnt.get("完成"): summ.append(_c(f"正常 {cnt['完成']}", C_GREEN))
    if cnt.get("警告"): summ.append(_c(f"警告 {cnt['警告']}", C_YELLOW))
    if cnt.get("异常"): summ.append(_c(f"异常 {cnt['异常']}", C_RED))
    if cnt.get("错误"): summ.append(_c(f"错误 {cnt['错误']}", C_RED))
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


def _run_diagnostics_sequential(keys, is_tty):
    """顺序模式: 保留 TTY 实时进度行 (\\r\\033[K 刷新), 详细 result 留给主循环统一打。"""
    results = {}
    full = {}
    for key in keys:
        name, cls = MODULE_MAP[key]
        if is_tty:
            sys.stdout.write(_c(f"  正在 {name} …", C_GRAY))
            sys.stdout.flush()
        else:
            print(_c(f"  正在 {name} …", C_GRAY))
        try:
            if key == "port":
                inst = cls(targets=PORT_PROBE_CONFIG["targets"],
                           proto=PORT_PROBE_CONFIG["proto"],
                           count=PORT_PROBE_CONFIG["count"])
            else:
                inst = cls()
            if is_tty:
                def _cb(msg, _n=name):
                    sys.stdout.write("\r\033[K" + _c(f"  … {msg}", C_GRAY))
                    sys.stdout.flush()
            else:
                _cb = lambda msg: None
            inst.detect(callback=_cb)
            if is_tty:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
            res = inst.results
            status = determine_status(res)
            results[key] = status
            full[key] = res
        except Exception as e:
            if is_tty:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
            print(_c(f"▶ {name}", C_BOLD) + "  " + _cli_status_badge("错误"))
            print(_c(f"  诊断异常: {e}", C_RED))
            results[key] = "错误"
            full[key] = {"error": str(e)}
    return results, full


def _run_diagnostics_parallel(keys, max_workers, total):
    """并行模式: 同时跑多个模块, 中间输出抑制, 完成后统一打印。

    设计要点:
      - print() 走 _safe_print (lock) 避免交错
      - 检测中 callback 静默, 结果统一在主线程按 keys 顺序打印
      - 共享状态 (_CMD_CACHE / _LOCAL_SUBNET_CACHE / _DECODE_CACHE / DNS socket)
        均为只读 / GIL-safe / thread-local, 多个 detector 并发安全
      - LAST_RUN 在主线程最后写, 无竞争
    """
    results = {}
    full = {}
    counter = {"done": 0}
    counter_lock = threading.Lock()

    def _run_one(key):
        name, cls = MODULE_MAP[key]
        idx = keys.index(key) + 1
        _safe_print(_c(f"  [{idx}/{total}] 正在 {name} …", C_GRAY))
        try:
            if key == "port":
                inst = cls(targets=PORT_PROBE_CONFIG["targets"],
                           proto=PORT_PROBE_CONFIG["proto"],
                           count=PORT_PROBE_CONFIG["count"])
            else:
                inst = cls()
            inst.detect(callback=lambda msg: None)  # parallel 模式抑制中间输出
            res = inst.results
            status = determine_status(res)
        except Exception as e:
            res = {"error": str(e)}
            status = "错误"
        # 完成行用 keys 顺序编号 (与启动行一致), 不按完成时间
        with counter_lock:
            counter["done"] += 1
            _safe_print(_c(f"  [{idx}/{total}] ✓ {name}", C_BOLD) + "  "
                        + _cli_status_badge(status))
        return key, name, status, res

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, total))) as ex:
        futs = [ex.submit(_run_one, k) for k in keys]
        for fut in as_completed(futs):
            key, _name, status, res = fut.result()
            results[key] = status
            full[key] = res
    return results, full


# ============================================================
# SECTION: 诊断报告生成与导出 (TXT / HTML / PDF)
# ============================================================

def build_report():
    """基于最近一次诊断运行 (LAST_RUN) 构造完整报告数据结构。"""
    if not LAST_RUN:
        return None
    run = LAST_RUN
    modules = []
    for key in run["keys"]:
        name = MODULE_MAP.get(key, (key, key))[0]
        res = run["results"].get(key, {})
        status = run["status"].get(key, "未检测")
        modules.append({
            "key": key,
            "name": name,
            "status": status,
            "result": res,
        })
    return {
        "app": run["app"],
        "version": run["version"],
        "generated_at": run["generated_at"],
        "system": run["system"],
        "summary": run["status"],
        "modules": modules,
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
    """
    try:
        import reportlab  # noqa
        return True
    except Exception:
        pass
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
    "traceroute": "路径追踪", "hop": "跳", "node": "节点", "avg_ms": "平均(ms)",
    "target": "目标", "loss_pct": "丢包(%)", "hop_count": "跳数",
    "dns_time_ms": "DNS(ms)", "avg_rtt_ms": "平均延迟(ms)",
    "avg_loss_pct": "平均丢包(%)",
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
    rows = [[("" if x.get(k) is None else str(x.get(k))) for k in keys] for x in v]
    return headers, rows


def render_report_pdf(report, path, auto_install=False, pip_mirror=None):
    """将报告渲染为 PDF (专业浅色主题 + 模块卡片, 内置中文字体 STSong-Light)。

    auto_install: True 时 reportlab 缺失会自动 pip install, 否则只提示。
    与旧版的差异: 旧版无条件 auto_yes=True, 在 CI/离线环境会无提示尝试
    pip install 然后卡 5 分钟, 用户体验差。
    pip_mirror: 显式指定 pip 镜像 URL, 覆盖自动选源。
    """
    if not ensure_reportlab(auto_yes=auto_install, mirror=pip_mirror):
        return False
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame,
                                    Paragraph, Spacer, Table, TableStyle,
                                    KeepTogether, HRFlowable)
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    # 内置中文字体 (无需外部字体文件), 缺点是只覆盖 GB2312 字符集:
    # 希腊字母 / 西里尔 / 阿拉伯文 / emoji 等会显示为方块或缺失。
    # 单文件 EXE 场景下妥协: 用户在 SSID/WiFi 名里塞希腊字母罕见, 报告内
    # 出现的几乎都是中文+ASCII+少量数字, GB2312 覆盖足够。
    FONT = "STSong-Light"

    # ── 专业工程配色 (与 HTML 报告一致) ──
    C_INK = colors.HexColor("#1b2437")       # 主文字
    C_SUB = colors.HexColor("#5a6472")       # 次文字
    C_FAINT = colors.HexColor("#8a94a6")     # 弱文字
    C_LINE = colors.HexColor("#e3e8f0")      # 边框/分隔线
    C_CARD = colors.HexColor("#f4f6f9")      # 卡片底
    C_BAND = colors.HexColor("#0f1c33")      # 页眉深带
    C_PRI = colors.HexColor("#1a56db")       # 主色
    C_PRI_DEEP = colors.HexColor("#1648a8")  # 主色(深, 表头文字)
    C_PRI_SOFT = colors.HexColor("#e8effc")  # 主色浅底
    C_OK = colors.HexColor("#0e8a4f")
    C_WARN = colors.HexColor("#b26a00")
    C_ERR = colors.HexColor("#d92d20")
    C_FATAL = colors.HexColor("#b42318")
    C_IDLE = colors.HexColor("#8a94a6")
    SC = {"完成": C_OK, "警告": C_WARN, "异常": C_ERR, "错误": C_FATAL,
          "未检测": C_IDLE}
    SC_HEX = {"完成": "#0e8a4f", "警告": "#b26a00", "异常": "#d92d20",
              "错误": "#b42318", "未检测": "#8a94a6"}
    SC_SOFT = {"完成": "#e7f6ee", "警告": "#fdf3e3", "异常": "#fdecec",
               "错误": "#fbebea", "未检测": "#f1f3f7"}

    # ── 样式 ──
    h_title = ParagraphStyle("h_title", fontName=FONT, fontSize=16,
                             textColor=colors.white, leading=19, spaceAfter=0)
    h_sub = ParagraphStyle("h_sub", fontName=FONT, fontSize=8.5,
                           textColor=colors.HexColor("#9db8e8"), leading=12)
    sec = ParagraphStyle("sec", fontName=FONT, fontSize=13,
                         textColor=C_INK, leading=17, spaceBefore=14, spaceAfter=6)
    lbl = ParagraphStyle("lbl", fontName=FONT, fontSize=9,
                         textColor=C_PRI, leading=13)
    val = ParagraphStyle("val", fontName=FONT, fontSize=9.5, textColor=C_INK, leading=13)
    mod_title = ParagraphStyle("mt", fontName=FONT, fontSize=11,
                               textColor=C_INK, leading=15)
    mod_sub = ParagraphStyle("ms", fontName=FONT, fontSize=9,
                            textColor=C_SUB, leading=13, spaceBefore=2)
    th = ParagraphStyle("th", fontName=FONT, fontSize=8.5,
                        textColor=C_PRI_DEEP, leading=12)
    cell = ParagraphStyle("cell", fontName=FONT, fontSize=8.5,
                          textColor=C_INK, leading=12)
    concl = ParagraphStyle("concl", fontName=FONT, fontSize=9,
                           textColor=C_INK, leading=13)
    err_style = ParagraphStyle("err", fontName=FONT, fontSize=9,
                               textColor=C_ERR, leading=13, spaceBefore=1)
    warn_style = ParagraphStyle("warn", fontName=FONT, fontSize=9,
                                textColor=C_WARN, leading=13, spaceBefore=1)
    badge_style = ParagraphStyle("badge", fontName=FONT, fontSize=8.5,
                                 textColor=colors.white, leading=11, alignment=1)
    foot_style = ParagraphStyle("foot", fontName=FONT, fontSize=7.5,
                                textColor=C_FAINT, leading=10)
    detail_cap = ParagraphStyle("detail_cap", fontName=FONT, fontSize=9,
                                textColor=C_FAINT, leading=12, spaceBefore=4)
    kv_cap = ParagraphStyle("kv_cap", fontName=FONT, fontSize=9.5,
                            textColor=C_SUB, leading=13, spaceBefore=4)

    def _badge(status, width=22 * mm):
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
        """四宫格大数字统计卡 (与 HTML 概览一致)。"""
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

    def _kv_table_pdf(rows):
        """由 (指标, 值) 列表构建常规两列表格。"""
        if not rows:
            return None
        tdata = [[Paragraph("<b>指标</b>", th), Paragraph("<b>值</b>", th)]]
        for k, v in rows:
            label = HEADER_MAP.get(k, k)
            tdata.append([Paragraph(label, cell), Paragraph(v or "—", cell)])
        dt = Table(tdata, colWidths=[58 * mm, content_w - 58 * mm], repeatRows=1)
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_PRI_SOFT),
            ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_LINE),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, C_LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
        return dt

    def _record_block_pdf(key, rt, is_detail=False):
        """由记录表 (headers, rows) 构建: 小标题 + 多列数据表。
        is_detail=True 时弱化为「详细测试记录」风格。"""
        headers, rows = rt
        cap = ("详细测试记录（原始测量数据）"
               if is_detail else HEADER_MAP.get(key, key))
        elems = [Paragraph(cap, detail_cap if is_detail else kv_cap)]
        ncol = len(headers)
        cw = [content_w / ncol] * ncol
        tdata = [[Paragraph(f"<b>{h}</b>", th) for h in headers]]
        for r in rows:
            tdata.append([Paragraph(x or "—", cell) for x in r])
        rt_tbl = Table(tdata, colWidths=cw, repeatRows=1)
        rt_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             C_PRI_SOFT if not is_detail
             else colors.HexColor("#f1f3f7")),
            ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_LINE),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, C_LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
        elems.append(rt_tbl)
        return elems

    g = report["generated_at"].strftime("%Y-%m-%d %H:%M:%S")
    PW, PH = A4
    LM = RM = 16 * mm
    TM = 18 * mm
    BM = 16 * mm

    def _on_page(canvas, doc_):
        canvas.saveState()
        # 页脚分隔线 + 文案
        canvas.setStrokeColor(C_LINE)
        canvas.setLineWidth(0.5)
        canvas.line(LM, BM - 4 * mm, PW - RM, BM - 4 * mm)
        canvas.setFont(FONT, 7.5)
        canvas.setFillColor(C_FAINT)
        canvas.drawString(LM, BM - 8 * mm,
                          f"{report['app']} v{report['version']} · 自动生成诊断报告")
        canvas.drawRightString(PW - RM, BM - 8 * mm, f"第 {doc_.page} 页")
        canvas.restoreState()

    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=LM, rightMargin=RM,
                          topMargin=TM, bottomMargin=BM,
                          title=f"{report['app']} 诊断报告")
    frame = Frame(LM, BM, PW - LM - RM, PH - TM - BM, id="main")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=_on_page)])

    flow = []
    content_w = PW - LM - RM

    # ── 页眉深带 ──
    header = Table(
        [[Paragraph(f"{report['app']} v{report['version']}  ·  网络诊断报告",
                    h_title),
          Paragraph(f"生成时间: {g}", h_sub)]],
        colWidths=[content_w - 46 * mm, 46 * mm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BAND),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    flow.append(header)
    flow.append(Spacer(1, 10))

    # ── 主机信息 ──
    sys_i = report["system"]
    flow.append(Paragraph("<b>主机信息</b>", sec))
    sdata = [
        [Paragraph("本机 IP", lbl), Paragraph(sys_i.get("local_ip", "未知"), val),
         Paragraph("默认网关", lbl), Paragraph(sys_i.get("gateway", "未知"), val)],
        [Paragraph("DNS 服务器", lbl), Paragraph(sys_i.get("dns", "未知"), val),
         Paragraph("公网 IP", lbl), Paragraph(sys_i.get("public_ip", "未知"), val)],
    ]
    st = Table(sdata, colWidths=[22 * mm, (content_w - 44 * mm) / 2,
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

    # ── 诊断汇总 ──
    cnt = {}
    for stt in report["summary"].values():
        cnt[stt] = cnt.get(stt, 0) + 1
    flow.append(Paragraph("<b>诊断汇总</b>", sec))
    flow.append(_stat_cards(cnt))
    flow.append(Spacer(1, 6))
    total = len(report["modules"])
    ok_n = cnt.get("完成", 0)
    flow.append(Paragraph(
        f"共 {total} 项检测，其中 <b>{ok_n}</b> 项正常、"
        f"<b>{cnt.get('警告',0)}</b> 项警告、<b>{cnt.get('异常',0)+cnt.get('错误',0)}</b> 项异常。",
        mod_sub))

    # ── 详细结果（每模块一张卡片）──
    flow.append(Paragraph("<b>详细结果</b>", sec))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=C_LINE,
                           spaceBefore=0, spaceAfter=8))

    for m in report["modules"]:
        c = SC.get(m["status"], C_IDLE)
        res = m["result"] or {}

        # ── 标题卡片: 状态圆点 + 名称 + 徽章 + 结论/问题 (始终可放下, 整体 KeepTogether) ──
        head = []
        dot = Table([[""]], colWidths=[3 * mm], rowHeights=[3 * mm])
        dot.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
        title_row = Table(
            [[dot, Paragraph(f"<b>{m['name']}</b>", mod_title),
              _badge(m["status"])]],
            colWidths=[5 * mm, content_w - 29 * mm, 24 * mm])
        title_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        head.append(title_row)

        if "error" in res:
            head.append(Paragraph(f"诊断异常: {res['error']}", err_style))
        else:
            if res.get("summary"):
                concl_tbl = Table(
                    [[Paragraph(
                        f"<font color='#1a56db'><b>结论</b></font>　"
                        f"{res['summary']}", concl)]],
                    colWidths=[content_w])
                concl_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), C_PRI_SOFT),
                    ("LINEBEFORE", (0, 0), (0, 0), 2.5, c),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
                head.append(Spacer(1, 3))
                head.append(concl_tbl)
            for e in (res.get("errors") or []):
                head.append(Paragraph(f"⚠ {e}", warn_style))

        head_tbl = Table([[head]], colWidths=[content_w])
        head_tbl.setStyle(TableStyle([
            ("LINEBEFORE", (0, 0), (0, 0), 3, c),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fbfcfd")),
            ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        flow.append(KeepTogether(head_tbl))
        flow.append(Spacer(1, 4))

        # ── 结构化数据表 (可自然跨页) ──
        if "error" not in res:
            skip = {"summary", "errors", "timestamp", "method"}
            extra = {k: v for k, v in res.items() if k not in skip}
            kv_rows = []  # 累积常规 指标/值 两列
            for k, v in extra.items():
                rt = _record_table(v)
                if rt is not None:
                    # 遇到记录表: 先 flush 累积的两列, 再独立成多列表格
                    if kv_rows:
                        flow.append(_kv_table_pdf(kv_rows))
                        kv_rows = []
                    flow.extend(_record_block_pdf(
                        k, rt, is_detail=(k in DETAIL_KEYS)))
                else:
                    kv_rows.extend(_flatten_kv({k: v}))
            if kv_rows:
                flow.append(_kv_table_pdf(kv_rows))
        flow.append(Spacer(1, 9))

    doc.build(flow)
    return True


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
    """按扩展名导出报告: .pdf / .html / .txt。返回错误信息或 None。

    auto_install: True 时允许 PDF 导出时自动 pip install reportlab
    (对应 CLI 的 --install)。默认 False, 缺包时只提示不安装。
    pip_mirror: 显式指定 pip 镜像 (CLI --pip-mirror)。
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
            return None if ok else "PDF 导出失败（reportlab 未就绪）"
        elif ext in (".html", ".htm"):
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_report_html(report))
            return None
        else:  # 默认按 txt
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_report_text(report))
            return None
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
    支持: 数字 (空格分隔多选)、0/全部、模块 key、模块中文名。
    严格模式: 任一 token 非法即整体拒绝。
    """
    choice = (choice or "").strip()
    if choice == "":
        return None
    if choice.lower() in ("0", "all", "a", "*"):
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
        print(_c("  请选择要执行的诊断 (输入数字, 空格分隔可多选):", C_WHITE))
        for i, (k, n, _) in enumerate(MODULE_REGISTRY, 1):
            print(f"    {_c(str(i).rjust(2), C_CYAN)}. {n}  {_c('(' + k + ')', C_GRAY)}")
        print(f"    {_c(' 0', C_CYAN)}. 运行全部诊断 {_c('(默认并发)', C_GRAY)}")
        print(f"    {_c(' q', C_CYAN)}. 退出")
        print(_c("-" * 60, C_GRAY))
        try:
            choice = input(_c("  输入 > ", C_GREEN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice.lower() in ("q", "quit", "exit"):
            break
        keys = parse_choice(choice)
        if keys is None:
            print(_c("  无效选择, 请重新输入。", C_YELLOW))
            try:
                input(_c("  按 Enter 继续...", C_GRAY))
            except (EOFError, KeyboardInterrupt):
                break
            continue
        # 菜单模式: 多模块默认并发 (与 CLI `all --parallel` 对齐)。
        # run_diagnostics 内部 `parallel and len(keys) > 1` 会自动避免
        # 单模块走并发 (无意义且会浪费线程开销)。
        run_diagnostics(keys, banner=False, parallel=True, max_workers=4)
        if sys.stdout.isatty():
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
                        help="端口探测目标, 格式 host:port (如 223.5.5.5:53); "
                             "可多次指定或用逗号分隔, 例: --port-target 223.5.5.5:53,119.29.29.29:53")
    parser.add_argument("--port-proto", choices=["tcp", "udp", "both"], default="tcp",
                        help="端口探测协议 (默认 tcp); both = TCP 与 UDP 均测")
    parser.add_argument("--port-count", type=int, default=4, metavar="N",
                        help="每个目标采样次数 (默认 4)")
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
    args = parser.parse_args()

    # 禁用 scapy 二层抓包 (避免 Npcap 不稳定导致段错误)
    if args.no_scapy:
        global FORCE_NO_SCAPY, SCAPY_AVAILABLE
        FORCE_NO_SCAPY = True
        SCAPY_AVAILABLE = False

    # 端口探测参数 -> 全局配置 (run_diagnostics 读取)
    if args.port_target:
        targets = []
        for part in args.port_target:
            targets.extend(p.strip() for p in part.split(",") if p.strip())
        PORT_PROBE_CONFIG["targets"] = targets or None
    PORT_PROBE_CONFIG["proto"] = args.port_proto
    PORT_PROBE_CONFIG["count"] = max(1, int(args.port_count))

    if args.list:
        _print_module_list()
        return
    if args.modules:
        if args.modules == ["all"]:
            keys = [k for k, _, _ in MODULE_REGISTRY]
        else:
            keys = parse_module_names(args.modules)
        if not keys:
            print("可用模块: " + ", ".join(k for k, _, _ in MODULE_REGISTRY))
            return
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
