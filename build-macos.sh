#!/usr/bin/env bash
# 在 macOS 上把「网络工具」打成 .app，再打成 ASCII 文件名的 zip。
# 用法：在项目根目录执行  bash build-macos.sh
set -euo pipefail
cd "$(dirname "$0")"

ARCH_RAW="$(uname -m)"
if [[ "$ARCH_RAW" == "x86_64" ]]; then
  ARCH="x64"
else
  ARCH="arm64"
fi
VER="${GITHUB_REF_NAME:-dev}"
APP_NAME="网络工具"

pick_python() {
  local c
  for c in python3.13 python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

PY="$(pick_python)" || { echo "未找到 Python 3，请先安装 Python 3.13"; exit 1; }
echo "使用解释器: $PY ($($PY -c 'import sys; print(sys.version.split()[0])'))  架构: $ARCH"

if [[ ! -d .venv ]]; then
  echo "创建虚拟环境 .venv ..."
  "$PY" -m venv .venv
fi
VENV_PY=".venv/bin/python"
"$VENV_PY" -m pip install -U pip
"$VENV_PY" -m pip install -r requirements.txt pyinstaller

# 生成 app.icns（sips / iconutil 为 macOS 自带）
mkdir -p build/AppIcon.iconset
SRC="icons/app-source.png"
if [[ ! -f "$SRC" ]]; then
  SRC="icons/app-64.png"
fi
if [[ ! -f "$SRC" ]]; then
  echo "缺少图标 icons/app-source.png 或 icons/app-64.png" >&2
  exit 1
fi
for s in 16 32 64 128 256 512 1024; do
  sips -z "$s" "$s" "$SRC" --out "build/AppIcon.iconset/icon_${s}x${s}.png" >/dev/null
  if [[ "$s" -lt 1024 ]]; then
    sips -z "$((s * 2))" "$((s * 2))" "$SRC" --out "build/AppIcon.iconset/icon_${s}x${s}@2x.png" >/dev/null
  fi
done
iconutil -c icns "build/AppIcon.iconset" -o "icons/app.icns"
echo "已生成 icons/app.icns"

# 内置 iperf3（优先使用已有 bin/iperf3，否则 brew）
if [[ ! -x bin/iperf3 ]]; then
  mkdir -p bin
  if command -v brew >/dev/null 2>&1; then
    brew list iperf3 >/dev/null 2>&1 || brew install iperf3
    IPERF="$(command -v iperf3 || true)"
    if [[ -n "$IPERF" ]]; then
      cp "$IPERF" bin/iperf3
      chmod +x bin/iperf3
      echo "已复制 iperf3 -> bin/iperf3"
    fi
  fi
fi

ADD_DATA=(--add-data "web:web" --add-data "icons:icons")
ADD_BIN=()
if [[ -x bin/iperf3 ]]; then
  ADD_BIN=(--add-binary "bin/iperf3:bin")
  echo "已包含 bin/iperf3"
else
  echo "未找到 bin/iperf3，将不内置 iperf3"
fi

echo "开始打包..."
"$VENV_PY" -m PyInstaller \
  --noconfirm --clean --windowed --onedir \
  --name "$APP_NAME" \
  --icon "icons/app.icns" \
  --osx-bundle-identifier "com.cnsunsz.wangluogongju" \
  --hidden-import webview \
  --hidden-import webview.platforms.cocoa \
  --hidden-import pystray \
  --hidden-import pystray._darwin \
  --hidden-import PIL \
  --hidden-import dns \
  --hidden-import qrcode \
  --hidden-import paramiko \
  --hidden-import cryptography \
  --hidden-import core.pktcap \
  --hidden-import core.pktcap.dissect \
  --hidden-import core.pktcap.pcapfile \
  --hidden-import core.pktcap.libpcap \
  --hidden-import core.pktcap.session \
  --hidden-import core.pktcap.analysis \
  --collect-all webview \
  --collect-all paramiko \
  --collect-all cryptography \
  "${ADD_DATA[@]}" \
  "${ADD_BIN[@]}" \
  app.py

APP="dist/${APP_NAME}.app"
if [[ ! -d "$APP" ]]; then
  echo "未生成 $APP" >&2
  exit 1
fi

ZIP_NAME="WangLuoGongJu-${VER}-macOS-${ARCH}.zip"
# ditto 保留 .app 包结构与 UTF-8 文件名
rm -f "dist/${ZIP_NAME}"
ditto -c -k --keepParent "$APP" "dist/${ZIP_NAME}"
SIZE="$(du -h "dist/${ZIP_NAME}" | awk '{print $1}')"
echo "完成：$APP"
echo "压缩包：dist/${ZIP_NAME}  ($SIZE)"
echo "未签名。用户需在「隐私与安全性」中允许，或右键「打开」。"
echo "运行时配置目录：~/Library/Application Support/网络工具/"
