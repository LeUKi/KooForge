use std::{
    fs::{self, File},
    io::{Write},
    path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::{bounded, Receiver, Sender};
use libp2p_identity::{Keypair, PeerId};
use libp2p_identity::ed25519;
use memchr::memmem;
use num_cpus;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ctrlc;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Any,
    Prefix,
    Suffix,
}

#[derive(Parser, Debug)]
#[command(name = "KooForge", author, version, about = "IPFS/IPNS Peer ID pattern-matching (vanity) generator (Ed25519, high performance) · IPFS/IPNS Peer ID 模式匹配（个性化 Vanity）生成器（Ed25519，高性能）", long_about = None)]
struct Args {
    pattern: Option<String>,

    /// Matching mode: any/prefix/suffix · 匹配模式：any/prefix/suffix
    #[arg(long, value_enum, default_value_t = Mode::Any)]
    mode: Mode,

    /// Threads (default: CPU logical cores) · 线程数（默认：CPU 逻辑核心数）
    #[arg(long)]
    threads: Option<usize>,

    /// Hit limit (default: 10; set 0 for unlimited) · 命中数量上限（默认：10；输入 0 为无限）
    #[arg(long)]
    limit: Option<usize>,

    /// Output directory (default: ./keystore) · 输出目录（默认：./keystore）
    #[arg(long, default_value = "keystore")]
    out: PathBuf,

    /// Case-insensitive match · 大小写不敏感匹配
    #[arg(long, default_value_t = false)]
    case_insensitive: bool,

    /// Print PeerId only, no private key write · 只打印 PeerId，不写入私钥
    #[arg(long, default_value_t = false)]
    print_only: bool,

    #[arg(long, default_value_t = 2)]
    stats_interval: u64,

    #[arg(long)]
    key_name: Option<String>,
    #[arg(long, default_value_t = false)]
    export_ipfs: bool,

    #[arg(long, default_value_t = false)]
    interactive: bool,

    #[arg(long, default_value_t = false)]
    no_color: bool,
}

#[derive(Debug, Clone)]
struct Hit {
    peer_id_b58: String,
    sk_protobuf: Option<Vec<u8>>, // libp2p protobuf 编码的私钥
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    if args.interactive || args.pattern.is_none() {
        args = interactive_args(args)?;
    }
    let threads = args.threads.unwrap_or_else(|| num_cpus::get());
    let stop = Arc::new(AtomicBool::new(false));
    let sig_count = Arc::new(AtomicUsize::new(0));

    {
        let stop = Arc::clone(&stop);
        let sig_count = Arc::clone(&sig_count);
        ctrlc::set_handler(move || {
            let n = sig_count.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                stop.store(true, Ordering::SeqCst);
                eprintln!("Stopping… Press Ctrl-C again to force exit · 正在停止…再次 Ctrl-C 强制退出");
            } else {
                std::process::exit(130);
            }
        })?;
    }

    if !args.print_only {
        fs::create_dir_all(&args.out)
            .with_context(|| format!("Failed to create output directory: {} · 创建输出目录失败: {}", args.out.display(), args.out.display()))?;
    }

    let (tx, rx) = bounded::<Hit>(1024);

    let pat = args.pattern.clone().expect("pattern required · 需要提供匹配子串");
    let pattern = if args.case_insensitive { pat.to_lowercase() } else { pat.clone() };

    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let tx = tx.clone();
        let pattern = pattern.clone();
        let mode = args.mode;
        let stop = Arc::clone(&stop);
        let case_insensitive = args.case_insensitive;
        let print_only = args.print_only;
        workers.push(thread::spawn(move || worker_loop(tx, stop, pattern, mode, case_insensitive, print_only)));
    }

    drop(tx);

    let eff_limit = match args.limit {
        Some(0) => None,
        Some(n) => Some(n),
        None => Some(10),
    };
    aggregator(rx, &args, stop.clone(), &pat, eff_limit)?;

    for h in workers { let _ = h.join(); }
    Ok(())
}

fn interactive_args(mut base: Args) -> Result<Args> {
    use dialoguer::{theme::ColorfulTheme, Input, Select, Confirm};
    let theme = ColorfulTheme::default();

    let pattern: String = Input::with_theme(&theme)
        .with_prompt("Match substring (Base58) · 匹配子串 (Base58)")
        .allow_empty(false)
        .interact_text()?;

    let modes = ["any", "prefix", "suffix"];
    let mode_idx = Select::with_theme(&theme)
        .with_prompt("Matching mode · 匹配模式")
        .items(&modes)
        .default(match base.mode { Mode::Any => 0, Mode::Prefix => 1, Mode::Suffix => 2 })
        .interact()?;
    let mode = match mode_idx { 0 => Mode::Any, 1 => Mode::Prefix, _ => Mode::Suffix };

    let def_threads = base.threads.unwrap_or_else(num_cpus::get);
    let threads: usize = Input::with_theme(&theme)
        .with_prompt("Threads · 线程数")
        .default(def_threads)
        .interact_text()?;

    let limit_str: String = Input::with_theme(&theme)
        .with_prompt("Hit limit (empty = default 10; 0 = unlimited) · 命中数量上限 (留空默认10；输入0为无限)")
        .allow_empty(true)
        .interact_text()?;
    let limit = if limit_str.trim().is_empty() { Some(10) } else {
        let n: usize = limit_str.trim().parse()?;
        if n == 0 { None } else { Some(n) }
    };

    let out_default = base.out.clone();
    let out_str: String = Input::with_theme(&theme)
        .with_prompt("Output directory · 输出目录")
        .default(out_default.display().to_string())
        .interact_text()?;
    let out = PathBuf::from(out_str);

    let case_insensitive = Confirm::with_theme(&theme)
        .with_prompt("Case-insensitive match? · 大小写不敏感匹配?")
        .default(base.case_insensitive)
        .interact()?;

    let print_only = Confirm::with_theme(&theme)
        .with_prompt("Print PeerId only (no private key)? · 只打印 PeerId (不写私钥)?")
        .default(base.print_only)
        .interact()?;

    let stats_interval: u64 = Input::with_theme(&theme)
        .with_prompt("Stats interval (seconds, 0=off) · 统计打印间隔(秒, 0关闭)")
        .default(base.stats_interval)
        .interact_text()?;

    let export_ipfs = Confirm::with_theme(&theme)
        .with_prompt("Export go-ipfs keystore file? · 导出 go-ipfs keystore 文件?")
        .default(base.export_ipfs)
        .interact()?;

    let key_name = if export_ipfs {
        let s: String = Input::with_theme(&theme)
            .with_prompt("Keystore filename · keystore 文件名")
            .allow_empty(false)
            .interact_text()?;
        Some(s)
    } else { None };

    base.pattern = Some(pattern);
    base.mode = mode;
    base.threads = Some(threads);
    base.limit = limit;
    base.out = out;
    base.case_insensitive = case_insensitive;
    base.print_only = print_only;
    base.stats_interval = stats_interval;
    base.export_ipfs = export_ipfs;
    base.key_name = key_name;
    let use_color = Confirm::with_theme(&theme)
        .with_prompt("Highlight matches? · 高亮显示匹配?")
        .default(!base.no_color)
        .interact()?;
    base.no_color = !use_color;
    base.interactive = false;
    Ok(base)
}

fn worker_loop(
    tx: Sender<Hit>,
    stop: Arc<AtomicBool>,
    pattern: String,
    mode: Mode,
    case_insensitive: bool,
    print_only: bool,
) {
    // 热路径循环：生成→派生→base58→匹配→命中发送
    while !stop.load(Ordering::Relaxed) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let mut kp_bytes = [0u8; 64];
        kp_bytes[..32].copy_from_slice(&sk.to_bytes());
        kp_bytes[32..].copy_from_slice(vk.as_bytes());
        let ed = ed25519::Keypair::try_from_bytes(&mut kp_bytes).expect("ed25519 key compose · 组装 ed25519 密钥失败");
        let kp = Keypair::from(ed);
        let pid = PeerId::from_public_key(&kp.public());
        let pid_b58 = bs58::encode(pid.to_bytes()).into_string();

        let matched = match mode {
            Mode::Any => contains(&pid_b58, &pattern, case_insensitive),
            Mode::Prefix => starts_with(&pid_b58, &pattern, case_insensitive),
            Mode::Suffix => ends_with(&pid_b58, &pattern, case_insensitive),
        };

        if matched {
            let sk_protobuf = if print_only { None } else { encode_private_key_protobuf(&kp).ok() };
            let _ = tx.send(Hit { peer_id_b58: pid_b58, sk_protobuf });
        }
    }
}

fn contains(hay: &str, needle: &str, ci: bool) -> bool {
    if ci { hay.to_lowercase().contains(&needle) } else { memmem::find(hay.as_bytes(), needle.as_bytes()).is_some() }
}
fn starts_with(hay: &str, needle: &str, ci: bool) -> bool {
    if ci { hay.to_lowercase().starts_with(&needle) } else { hay.starts_with(needle) }
}
fn ends_with(hay: &str, needle: &str, ci: bool) -> bool {
    if ci { hay.to_lowercase().ends_with(&needle) } else { hay.ends_with(needle) }
}

fn aggregator(rx: Receiver<Hit>, args: &Args, stop: Arc<AtomicBool>, pat: &str, eff_limit: Option<usize>) -> Result<()> {
    let mut found = 0usize;
    let mut last_stats = OffsetDateTime::now_utc();
    let mut generated_counter: u64 = 0; // 简易估计：以命中作为可见事件，不统计总生成数（可扩展）

    loop {
        if stop.load(Ordering::Relaxed) { break; }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(hit) => {
                found += 1;
                generated_counter += 1;
                let out = if args.no_color { hit.peer_id_b58.clone() } else { highlight(&hit.peer_id_b58, pat, args.mode, args.case_insensitive) };
                println!("{}", out);
                if let Some(sk) = hit.sk_protobuf {
                    write_key(&args.out, &hit.peer_id_b58, &sk)?;
                    if args.export_ipfs {
                        if let Some(name) = &args.key_name {
                            write_named_key(&args.out, name, &sk)?;
                        }
                    }
                }
                if let Some(limit) = eff_limit { if found >= limit { stop.store(true, Ordering::Relaxed); break; } }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {},
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }

        if args.stats_interval > 0 {
            let now = OffsetDateTime::now_utc();
            let secs = (now - last_stats).whole_seconds();
            if secs >= args.stats_interval as i64 {
                println!("[stats 统计 {}] hits/命中={}, threads/线程={}, mode/模式={:?}", now.format(&Rfc3339)?, found, args.threads.unwrap_or_else(num_cpus::get), args.mode);
                last_stats = now;
            }
        }
    }

    Ok(())
}

fn write_key(out_dir: &Path, peer_id_b58: &str, sk_protobuf: &[u8]) -> Result<()> {
    let key_path = out_dir.join(peer_id_b58);
    let tmp = out_dir.join(format!("{}.tmp", peer_id_b58));
    {
        let mut f = File::create(&tmp).with_context(|| format!("Failed to create temp file: {} · 创建临时文件失败: {}", tmp.display(), tmp.display()))?;
        f.write_all(sk_protobuf)?;
        f.flush()?;
    }
    fs::rename(&tmp, &key_path).with_context(|| format!("Atomic rename failed: {} · 原子重命名失败: {}", key_path.display(), key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&key_path)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&key_path, perm)?;
    }

    // 额外写入 peerid 文本，方便引用
    let pid_txt = out_dir.join(format!("{}-peerid.txt", peer_id_b58));
    fs::write(pid_txt, peer_id_b58.as_bytes())?;
    Ok(())
}

fn write_named_key(out_dir: &Path, name: &str, sk_protobuf: &[u8]) -> Result<()> {
    let key_path = out_dir.join(name);
    let tmp = out_dir.join(format!("{}.tmp", name));
    {
        let mut f = File::create(&tmp).with_context(|| format!("Failed to create temp file: {} · 创建临时文件失败: {}", tmp.display(), tmp.display()))?;
        f.write_all(sk_protobuf)?;
        f.flush()?;
    }
    fs::rename(&tmp, &key_path).with_context(|| format!("Atomic rename failed: {} · 原子重命名失败: {}", key_path.display(), key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&key_path)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&key_path, perm)?;
    }
    Ok(())
}

fn encode_private_key_protobuf(kp: &Keypair) -> Result<Vec<u8>> {
    let bytes = kp.to_protobuf_encoding()?;
    Ok(bytes)
}

fn highlight(hay: &str, needle: &str, mode: Mode, ci: bool) -> String {
    let start = match mode {
        Mode::Prefix => Some(0),
        Mode::Suffix => hay.len().checked_sub(needle.len()),
        Mode::Any => {
            if ci {
                let h = hay.to_lowercase();
                h.find(&needle.to_lowercase())
            } else {
                memmem::find(hay.as_bytes(), needle.as_bytes())
            }
        }
    };
    if let Some(s) = start {
        let e = s.saturating_add(needle.len());
        let pre = &hay[..s];
        let mid = &hay[s..e];
        let post = &hay[e..];
        let esc_on = "\x1b[1;32m";
        let esc_off = "\x1b[0m";
        format!("{}{}{}{}{}", pre, esc_on, mid, esc_off, post)
    } else {
        hay.to_string()
    }
}
