<h1 align="center">KooForge</h1>
<p align="center">高速、交互友好的 IPFS/IPNS Peer ID 模式匹配（个性化 Vanity）生成器 · Rust</p>
<p align="center"><a href="./README.md">English</a></p>

<p align="center">
  <a href="https://github.com/LeUKi/kooforge"><img src="https://img.shields.io/badge/GitHub-LeUKi%2Fkooforge-blue" alt="GitHub"></a>
  <a href="./LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License"></a>
  <a href="./LICENSE-APACHE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue" alt="Apache-2.0 License"></a>
</p>

<p align="center"><i>为你的节点铸造理想的 Peer ID</i></p>

---

## 特性
- Ed25519 生成（与 IPFS/Libp2p 完全兼容，较 RSA 更快）。
- 多线程并行，热路径零锁；仅命中才写盘，最大化吞吐。
- 支持任意子串/前缀/后缀匹配；可大小写不敏感。
- 命中日志高亮显示匹配片段，便于快速确认。
- 交互模式引导参数输入并带默认值；无需记忆命令行。
- 一键导出为 go-ipfs keystore 文件名，直接用于 `ipfs name publish`。

## 安装
- `cargo install --git https://github.com/LeUKi/kooforge`

## 快速开始
```
# 交互模式：逐步选择匹配模式/线程数/是否导出等
kooforge

# 前缀匹配（命中 1 个后退出）
kooforge 12 --mode prefix --limit 1

# 任意子串匹配（默认大小写不敏感，8 线程）
kooforge KoOw --mode any --threads 8

# 导出为 go-ipfs keystore（文件名为 dupa）
kooforge dupa --mode any --limit 1 --export-ipfs --key-name dupa
cp keystore/dupa ~/.ipfs/keystore/dupa
ipfs name publish --key=dupa {ipfs-path}
```

## 命令行参数
- `pattern`：要匹配的 Base58 子串（交互模式下可省略）。
- `--mode [any|prefix|suffix]`：匹配模式，默认 `any`。
- `--threads N`：线程数，默认为 CPU 逻辑核心数。
- `--limit N`：命中数量上限；默认 10；设置 `0` 为无限。
- `--out DIR`：输出目录，默认 `keystore`。
- `--case-insensitive`：大小写不敏感匹配（默认开启）。
- `--case-sensitive`：强制大小写敏感匹配（覆盖上述设置）。
- `--print-only`：只打印 PeerId，不写入私钥文件。
- `--stats-interval SECS`：统计打印间隔（秒；`0` 关闭）。
- `--export-ipfs`：使用 `--key-name` 额外落盘兼容 go-ipfs keystore。
- `--key-name NAME`：导出到 keystore 的文件名。
- `--no-color`：关闭命中高亮显示。
- `--interactive`：进入交互界面引导输入参数。

## 输出与兼容性
- 默认将命中的私钥写入 `./keystore/`，文件名为该 `PeerId`；内容为 libp2p 私钥 protobuf 编码。
- 开启 `--export-ipfs --key-name NAME` 后，额外写入 `./keystore/NAME`，可直接复制到 `~/.ipfs/keystore/NAME`。
- 日志打印命中的 `PeerId`，匹配片段以 ANSI 高亮显示（`--no-color` 可关闭）。

## 性能建议
- 使用 Ed25519（与 RSA 相比生成速度数量级提升，且与 IPFS/Libp2p 生态兼容）。
- 构建使用 `--release`，并启用本机指令集优化：`-C target-cpu=native`。
- 在热路径避免正则和不必要分配；仅命中项通过通道传递并写盘。
- 前缀/后缀匹配更容易命中并减少搜索时间；任意子串匹配更耗时。

## 安全
- 不在日志中输出私钥；写盘采用原子写并在 Unix 上设置权限为 `600`。
- 请妥善备份私钥文件并限制访问权限，避免泄露。

## 为什么叫 KooForge
- “Koo” 呼应 IPFS/Libp2p 生态中常见的 `12D3Koo` Peer ID 前缀。
- “Forge” 表示“锻造、铸造”，强调按你想要的模式生成 Peer ID。
- 名字简短好记，与工具目的高度贴合。

## 致谢
- 灵感与目标参考了 IPFS/IPNS 生态的相关工具与实践。
