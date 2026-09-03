#!/usr/bin/env bash
# v2 编码：edge-tts 输出 24kHz mono (非标准, 兼容性差), 在 mux 前重采样到 48kHz stereo.
set -euo pipefail
cd "D:/Work/Projects/NetPulse/video_promo"

FPS=30
W=1280
H=720
TOTAL=$(node -e "console.log(JSON.parse(require('fs').readFileSync('narr1/narr_meta.json','utf8')).total)")
echo "TOTAL=$TOTAL"

# 1) frames/ → 无声 mp4
echo "[1/4] encoding frames -> silent mp4 ..."
ffmpeg -y -r "$FPS" -i frames/frame_%05d.png \
    -c:v libx264 -pix_fmt yuv420p -preset slow -crf 18 \
    -vf "scale=${W}:${H}" \
    -movflags +faststart \
    _silent.mp4 2>&1 | tail -4

# 2) 拼旁白 → 24kHz mono voice_raw
echo "[2/4] concatenating narration mp3s ..."
cd narr1
ffmpeg -y -f concat -safe 0 -i list.txt -c copy voice_raw.mp3 2>&1 | tail -2
cd ..
DUR=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 narr1/voice_raw.mp3)
PAD=$(node -e "console.log(Math.max(0, ($TOTAL - $DUR)).toFixed(3))")
echo "  voice_raw=$DUR  pad_needed=$PAD"

# 3) 把 voice_raw 重采样到 48kHz stereo, 末尾按 PAD 补静音 (48kHz stereo 静音)
#    一气呵成: concat [voice_raw_normalized] + [silence]
echo "[3/4] resample to 48kHz stereo + pad silence ..."
if [ "$(node -e "console.log($PAD > 0.05 ? 'y' : 'n')")" = "y" ]; then
    ffmpeg -y -i narr1/voice_raw.mp3 \
        -f lavfi -t "$PAD" -i "anullsrc=r=48000:cl=stereo" \
        -filter_complex "
            [0:a]aresample=48000,aformat=channel_layouts=stereo[a0];
            [1:a]aresample=48000,aformat=channel_layouts=stereo[a1];
            [a0][a1]concat=n=2:v=0:a=1[a]
        " -map "[a]" \
        -c:a pcm_s16le narr1/voice_full.wav 2>&1 | tail -3
else
    ffmpeg -y -i narr1/voice_raw.mp3 \
        -filter_complex "aresample=48000,aformat=channel_layouts=stereo" \
        -c:a pcm_s16le narr1/voice_full.wav 2>&1 | tail -3
fi
ffprobe -v error -show_entries stream=codec_name,sample_rate,channels -of default=noprint_wrappers=1 narr1/voice_full.wav

# 4) mux: 视频 -t TOTAL, 音频 wav → aac 128k
echo "[4/4] muxing final mp4 ..."
ffmpeg -y -i _silent.mp4 -i narr1/voice_full.wav \
    -map 0:v -map 1:a \
    -c:v copy -c:a aac -b:a 192k -ar 48000 -ac 2 \
    -t "$TOTAL" -shortest -movflags +faststart \
    case_video_netpulse.mp4 2>&1 | tail -3

# 5) 验证
echo "=== verify ==="
ffprobe -v error -show_entries stream=codec_type,codec_name,sample_rate,channels,duration,nb_frames -of default=noprint_wrappers=1 case_video_netpulse.mp4
echo "--- 音视频差 ---"
ffprobe -v error -select_streams v -show_entries stream=duration -of default=noprint_wrappers=1:nokey=1 case_video_netpulse.mp4 > /tmp/v.txt
ffprobe -v error -select_streams a -show_entries stream=duration -of default=noprint_wrappers=1:nokey=1 case_video_netpulse.mp4 > /tmp/a.txt
V=$(cat /tmp/v.txt); A=$(cat /tmp/a.txt)
echo "video=$V  audio=$A  diff=$(node -e "console.log(Math.abs($V - $A).toFixed(3))")s"
ffmpeg -i case_video_netpulse.mp4 -af volumedetect -f null - 2>&1 | grep -E "mean_volume|max_volume"
ls -lh case_video_netpulse.mp4