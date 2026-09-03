#!/usr/bin/env python3
"""NetPulse 推广视频 · 8 段旁白生成（edge-tts YunyangNeural 男声）"""
import asyncio, os, json, subprocess
import edge_tts

BASE = "D:/Work/Projects/NetPulse/video_promo"
VOICE = "zh-CN-YunyangNeural"   # 男声 · 专业沉稳（沿用前两期）
RATE = "+2%"
GAP = 0.4     # 段间停顿（秒）
HOLD = 3.0    # 片尾停留（秒）
OUT = os.path.join(BASE, "narr1")

# 8 段旁白；scene 0..7 对应 S1..S8。
# 多音字规避（沿用前两期）：转->仅在"路径MTU"读 zhuǎn（无歧义）；卡->卡顿；
# 重->避免"重传"歧义，改"重发"或"重复"；行->约 háng；为->读 wèi；
# 薄->单字读 báo 在"薄弱"；行->háng 在"宽泛"。"reg"按字母读。
# 受众定位：装维人员（源码 netpulse.py:15090 注释「报告受众是装维人员」）。
# 全片一律同行口吻，不对客户说话；客户只作为场景里的服务对象出现（第三人称）。
# 技术事实全部核过源码：
#   · PMTU 判定 = A 或 (B∧C)；仅 B 判 tcp_loss（netpulse.py:12107）
#   · Bufferbloat 建议 = 开 SQM/QoS、查上联订阅、换 fq_codel/CAKE（:1728-1732）
#   · 千兆协商到百兆是不达标首因，测速上限约 94M（:15093）
#   · slow 场景 = 7 个模块（:2394）
#   · MTU 不匹配阈值 = 接口减路径 ≥100，PPPoE 1492 不误报（:10755）
# 行话复用 MODULE_EXPLAINS：网线芯数 / 水晶头 / 办理档位 / 下载时全家卡。
SEGMENTS = [
    {"scene": 0, "text": "兄弟们，上门就带这一个——NetPulse。25MB，单文件 exe，双击就跑，常规诊断无需另装依赖、配环境。到了用户家，U盘一插、点两下，场景菜单就出来了：网速慢、经常断网、网页打不开、游戏延迟高、WiFi信号差——用户报的是啥现象，你就选哪一项。"},
    {"scene": 1, "text": "最常接的活儿就是网速慢。到现场一测，能 ping 通、DNS解析正常、测速也够，用户就是说卡。选'网络很慢'，7 个模块一口气跑完。它不只说通不通，还直接给根因：空闲时延迟20毫秒，一下载就飙到300多毫秒——这是典型 bufferbloat，大概率是路由器缓存/队列管理不佳，在路由器上开启 SQM 智能队列管理就能压下去。每条结论带证据链和已排除项，不用靠猜。"},
    {"scene": 2, "text": "另一种活最熬人——偶发掉线。用户说一天断好几回，你上门一测稳得很；人刚走，故障单又来了。现在可以开'盯障模式'：现场挂 30 分钟，时间可调，ping、TCP 建连、DNS 解析后台持续监测，还能模拟下载负载，把偶发中断和'平时小包正常、大包传输才异常'的问题逼出来。收工看报告：哪一分钟断的、断了多少秒、断在内网侧还是运营商侧，证据链齐全，有理有据。"},
    {"scene": 3, "text": "网页打不开、ping IP 却通，这种最邪门，先别急着改 DNS。选'网页打不开'，8 个模块一起跑：一边把开网页拆成 DNS 解析、TCP 建连、TLS 握手、首字节时间四段计时；一边二分探测路径 MTU。ping 小包看不出的盲区就在这——MTU 不匹配的典型症状是：小包小文件基本正常，大文件、大图片、较大 CSS/JS 或部分 HTTPS 站点加载卡住、超时。改法三条：本机 MTU 降下来、路由器配置 MSS 钳制、联系支撑人员核对链路 MTU。"},
    {"scene": 4, "text": "千兆测速不达标，先看链路协商，这是最常见的坑。千兆口一旦协商成百兆，测速理论上限约 94Mbps。优先检查网线是否只接了 4 芯、水晶头是否压接不良或线序错误——这是千兆降百兆最常见的原因。协商正常还是慢，再看 WiFi 信道：2.4G 在 20MHz 带宽下只有 1、6、11 三个不重叠信道，邻居全挤在 1 上，你换到 11 就清净。信道拥挤是 WiFi 慢、宽带本身没事。这两样 NetPulse 一张图摆齐。"},
    {"scene": 5, "text": "啃不动的硬骨头，上盯障加抓包。管理员权限开一次，按提示装好 Npcap，剩下的它自己干：断网事件前后各 30 秒 pcap 自动切片，Wireshark 直接打开。PMTU 黑洞重点看三个信号：A，抓到'需要分片'的 ICMP 且带下一跳 MTU；B，大包同序号反复重传或没有确认，小包还在流；C，TCP 握手 MSS 大于路径 MTU 减 40。A 能抓到，说明路径 MTU 已经暴露，按 MTU 问题处理；B 和 C 同时出现、又抓不到 A，才更像 PMTU 黑洞。只有 B，先按链路丢包查，要结合抓包进一步区分。"},
    {"scene": 6, "text": "跑完一键导出 HTML 报告：健康分、待办清单、根因摘要、证据链、复测命令，一页装齐，行话指标都配通俗解释。最省事的是一句话报障卡，点一下复制：'千兆测速不达标，网口协商 100Mbps，网线仅 4 芯，已更换后复测达标'，直接发工作群、贴工单。用户要纸质凭证？Ctrl+P 现场打一张。"},
    {"scene": 7, "text": "NetPulse，单文件 Windows 网络诊断工具。常规诊断零依赖，23 个模块，辅助根因分析，盯障取证。抓包模块按需安装 Npcap。GitHub 开源，MIT 协议，免费用。兄弟们，赶紧下载试试。"},
]


def ffprobe_dur(path):
    out = subprocess.check_output([
        "ffprobe", "-v", "error", "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1", path
    ])
    return float(out.strip())


async def main():
    os.makedirs(OUT, exist_ok=True)
    # ONLY_SCENE=<0-7> 只重新合成该段（其余沿用已有 mp3），meta/list 仍全量重建
    only = os.environ.get("ONLY_SCENE")
    only_idx = int(only) if only is not None else None
    segs = []
    for i, item in enumerate(SEGMENTS):
        dst = os.path.join(OUT, f"scene_{i+1:02d}.mp3")
        if only_idx is None or i == only_idx or not os.path.exists(dst):
            await edge_tts.Communicate(item["text"], VOICE, rate=RATE).save(dst)
        d = ffprobe_dur(dst)
        segs.append({"idx": i, "scene": item["scene"], "text": item["text"],
                     "file": dst, "dur": round(d, 3)})
        print(f"scene {i+1}: {len(item['text'])} chars -> {d:.2f}s  {dst}")
    start = 0.0
    for s in segs:
        s["start"] = round(start, 3)
        start = start + s["dur"] + GAP
    scene_start = {}
    for s in segs:
        scene_start.setdefault(s["scene"], s["start"])
    markers = [scene_start[sc] for sc in range(8)]
    cta_start = segs[-1]["start"]
    total = round(segs[-1]["start"] + segs[-1]["dur"] + HOLD, 3)
    meta = {
        "segments": segs,
        "markers": markers,
        "cta_start": cta_start,
        "gap": GAP,
        "hold": HOLD,
        "total": total,
    }
    with open(os.path.join(OUT, "narr_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    silence = os.path.join(OUT, "silence.mp3")
    subprocess.check_call([
        "ffmpeg", "-y", "-f", "lavfi", "-i", "anullsrc=r=24000:cl=mono",
        "-t", str(GAP), "-c:a", "libmp3lame", "-b:a", "64k", silence
    ])
    with open(os.path.join(OUT, "list.txt"), "w", encoding="utf-8") as f:
        for idx, s in enumerate(segs):
            f.write(f"file '{os.path.basename(s['file'])}'\n")
            if idx < len(segs) - 1:
                f.write(f"file 'silence.mp3'\n")
    print("ALL_DONE total=", total, "markers=", markers, "cta_start=", cta_start)


if __name__ == "__main__":
    asyncio.run(main())
