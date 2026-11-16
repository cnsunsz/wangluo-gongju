# 可选：iperf3 二进制

本目录默认不含可执行文件。若要把 iperf3 测速功能打进「网络工具.exe」：

1. 从 https://iperf.fr/iperf-download.php 下载 Windows 版 iperf3。
2. 将 `iperf3.exe` 和其依赖的 `cygwin1.dll`（若发行包提供）放到本目录。
3. 再运行 `build.ps1` / `build.bat`。构建脚本在这两个文件存在时会自动 `--add-binary` 打进 exe。

也可以不打包，运行时把 `iperf3.exe` 放到系统 PATH 或与「网络工具.exe」同一目录。
