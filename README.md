<h1 align="center">KooForge</h1>
<p align="center">A fast, interactive IPFS/IPNS Peer ID vanity generator in Rust</p>
<p align="center"><a href="./README-CN.md">中文说明</a></p>

<p align="center">
  <a href="https://github.com/LeUKi/kooforge"><img src="https://img.shields.io/badge/GitHub-LeUKi%2Fkooforge-blue" alt="GitHub"></a>
  <a href="./LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License"></a>
  <a href="./LICENSE-APACHE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue" alt="Apache-2.0 License"></a>
</p>

<p align="center"><i>Forge the Peer ID You Want</i></p>

---

## Features
- Ed25519 key generation (fully compatible with IPFS/Libp2p; significantly faster than RSA).
- Multi-threaded generation with zero locks on the hot path; disk I/O only on matches.
- Flexible matching: substring, prefix, and suffix; optional case-insensitive mode.
- Highlight matched segment in logs for quick visual confirmation.
- Interactive mode to guide parameter input with sensible defaults.
- Export directly to a go-ipfs compatible keystore filename for `ipfs name publish`.

## Installation
-  `cargo install --git https://github.com/LeUKi/kooforge`

## Quick Start
```
# Interactive mode: step through mode/threads/export etc.
kooforge

# Prefix match (stop after first hit)
kooforge 12 --mode prefix --limit 1

# Substring match (default case-insensitive, 8 threads)
kooforge KoOw --mode any --threads 8

# Export as go-ipfs keystore (filename: dupa)
kooforge dupa --mode any --limit 1 --export-ipfs --key-name dupa
cp keystore/dupa ~/.ipfs/keystore/dupa
ipfs name publish --key=dupa {ipfs-path}
```

## CLI Options
- `pattern`: Base58 substring to match (optional in interactive mode).
- `--mode [any|prefix|suffix]`: matching mode; default `any`.
- `--threads N`: number of threads; defaults to CPU logical cores.
- `--limit N`: stop after N matches; default 10; set `0` for unlimited.
- `--out DIR`: output directory; default `keystore`.
- `--case-insensitive`: case-insensitive matching (default on).
- `--case-sensitive`: force case-sensitive matching (overrides above).
- `--print-only`: print PeerId only; do not write the private key.
- `--stats-interval SECS`: stats print interval in seconds; `0` disables.
- `--export-ipfs`: also write a go-ipfs compatible keystore file using `--key-name`.
- `--key-name NAME`: filename for the keystore export.
- `--no-color`: disable match highlighting.
- `--interactive`: interactive parameter prompts.

## Output & Compatibility
- On match, writes the private key to `./keystore/` named by the `PeerId`; encoded using libp2p protobuf.
- With `--export-ipfs --key-name NAME`, additionally writes `./keystore/NAME`, ready to copy to `~/.ipfs/keystore/NAME`.
- Logs print the matched `PeerId` with ANSI highlighting (disable via `--no-color`).

## Performance Tips
- Use Ed25519 for best throughput and full IPFS/Libp2p compatibility.
- Build with `--release` and enable native CPU optimizations: `-C target-cpu=native`.
- Avoid regex and excessive allocations on the hot path; only send/write on matches.
- Prefix/suffix matches tend to hit faster than arbitrary substrings.

## Security
- Private keys are never logged; writes use atomic file moves and `0600` permissions on Unix.
- Store keystore files securely and restrict access to prevent leakage.

## Why KooForge
- "Koo" nods to the common `12D3Koo` Peer ID prefix in the IPFS/Libp2p ecosystem.
- "Forge" highlights the act of crafting IDs that match your desired pattern.
- Short, memorable, and directly tied to the tool’s purpose.

## Acknowledgements
- Inspired by tooling and best practices in the IPFS/IPNS ecosystem.
