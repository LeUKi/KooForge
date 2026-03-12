use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::{bounded, Receiver, Sender};
use ctrlc;
use ed25519_dalek::SigningKey;
use libp2p_identity::ed25519;
use libp2p_identity::{Keypair, PeerId};
use memchr::memmem;
use num_cpus;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Any,
    Prefix,
    Suffix,
}

const BASE58BTC_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const REQUIRED_PREFIX: &str = "12D3KooW";
const ED25519_PEER_ID_MULTIHASH_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

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

    /// Case-insensitive match (default: on) · 大小写不敏感匹配（默认开启）
    #[arg(long, default_value_t = false)]
    case_insensitive: bool,

    /// Force case-sensitive match (overrides above) · 强制大小写敏感匹配（覆盖上述设置）
    #[arg(long, default_value_t = false)]
    case_sensitive: bool,

    /// Print PeerId only, no private key write · 只打印 PeerId，不写入私钥
    #[arg(long, default_value_t = false)]
    print_only: bool,

    #[arg(long)]
    stats_interval: Option<u64>,

    #[arg(long)]
    key_name: Option<String>,
    #[arg(long, default_value_t = false)]
    export_ipfs: bool,

    #[arg(long, default_value_t = false)]
    interactive: bool,

    #[arg(long, default_value_t = false)]
    no_color: bool,

    /// Extreme performance mode (force case-sensitive, disable stats by default) · 极致性能模式（强制大小写敏感，默认关闭统计）
    #[arg(long, default_value_t = false)]
    extreme: bool,
}

#[derive(Debug, Clone)]
struct Hit {
    peer_id_b58: String,
    sk_protobuf: Option<Vec<u8>>, // libp2p protobuf 编码的私钥
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    let used_guided_input = args.interactive || args.pattern.is_none();
    if used_guided_input {
        args = interactive_args(args)?;
    }
    preprocess_args(&mut args)?;
    if used_guided_input {
        eprintln!(
            "Equivalent command (guided input) · 引导输入对应的命令:\n{}",
            build_equivalent_command(&args)
        );
    }
    let threads = args.threads.unwrap_or_else(|| num_cpus::get());
    let stop = Arc::new(AtomicBool::new(false));
    let sig_count = Arc::new(AtomicUsize::new(0));
    let total_attempts = Arc::new(AtomicU64::new(0));

    {
        let stop = Arc::clone(&stop);
        let sig_count = Arc::clone(&sig_count);
        ctrlc::set_handler(move || {
            let n = sig_count.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                stop.store(true, Ordering::SeqCst);
                eprintln!(
                    "Stopping… Press Ctrl-C again to force exit · 正在停止…再次 Ctrl-C 强制退出"
                );
            } else {
                std::process::exit(130);
            }
        })?;
    }

    if !args.print_only {
        fs::create_dir_all(&args.out).with_context(|| {
            format!(
                "Failed to create output directory: {} · 创建输出目录失败: {}",
                args.out.display(),
                args.out.display()
            )
        })?;
    }

    let (tx, rx) = bounded::<Hit>(1024);

    let pat = args
        .pattern
        .clone()
        .expect("pattern required · 需要提供匹配子串");
    let ci_eff = effective_case_insensitive(&args);
    let matcher = Matcher::new(args.mode, ci_eff, &pat);
    let stats_interval = resolve_stats_interval(args.stats_interval, args.extreme);

    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let tx = tx.clone();
        let matcher = matcher.clone();
        let extreme = args.extreme;
        let stop = Arc::clone(&stop);
        let print_only = args.print_only;
        let total_attempts = Arc::clone(&total_attempts);
        workers.push(thread::spawn(move || {
            if extreme {
                worker_loop_extreme(tx, stop, matcher, print_only, total_attempts)
            } else {
                worker_loop_standard(tx, stop, matcher, print_only, total_attempts)
            }
        }));
    }

    drop(tx);

    let eff_limit = resolve_effective_limit(args.limit);
    aggregator(
        rx,
        &args,
        stop.clone(),
        &pat,
        eff_limit,
        ci_eff,
        stats_interval,
        total_attempts,
    )?;

    for h in workers {
        let _ = h.join();
    }
    Ok(())
}

fn interactive_args(mut base: Args) -> Result<Args> {
    use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
    let theme = ColorfulTheme::default();

    let pattern: String = Input::with_theme(&theme)
        .with_prompt("Match substring (Base58) · 匹配子串 (Base58)")
        .allow_empty(false)
        .validate_with(|input: &String| -> std::result::Result<(), String> {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return Err("Pattern cannot be empty · 匹配子串不能为空".to_string());
            }
            validate_base58_pattern(trimmed).map_err(|e| e.to_string())
        })
        .interact_text()?;

    let modes = ["any", "prefix", "suffix"];
    let mode_idx = Select::with_theme(&theme)
        .with_prompt("Matching mode · 匹配模式")
        .items(&modes)
        .default(match base.mode {
            Mode::Any => 0,
            Mode::Prefix => 1,
            Mode::Suffix => 2,
        })
        .interact()?;
    let mode = match mode_idx {
        0 => Mode::Any,
        1 => Mode::Prefix,
        _ => Mode::Suffix,
    };

    let def_threads = base.threads.unwrap_or_else(num_cpus::get);
    let threads: usize = Input::with_theme(&theme)
        .with_prompt("Threads · 线程数")
        .default(def_threads)
        .interact_text()?;

    let limit_str: String = Input::with_theme(&theme)
        .with_prompt("Hit limit (empty = default 10; 0 = unlimited) · 命中数量上限 (留空默认10；输入0为无限)")
        .allow_empty(true)
        .interact_text()?;
    let limit = if limit_str.trim().is_empty() {
        None
    } else {
        let n: usize = limit_str.trim().parse()?;
        Some(n)
    };

    let out_default = base.out.clone();
    let out_str: String = Input::with_theme(&theme)
        .with_prompt("Output directory · 输出目录")
        .default(out_default.display().to_string())
        .interact_text()?;
    let out = PathBuf::from(out_str);

    let case_insensitive = Confirm::with_theme(&theme)
        .with_prompt("Case-insensitive match? · 大小写不敏感匹配?")
        .default(effective_case_insensitive(&base))
        .interact()?;

    let extreme = Confirm::with_theme(&theme)
        .with_prompt("Enable extreme performance mode? · 启用极致性能模式?")
        .default(base.extreme)
        .interact()?;

    let print_only = Confirm::with_theme(&theme)
        .with_prompt("Print PeerId only (no private key)? · 只打印 PeerId (不写私钥)?")
        .default(base.print_only)
        .interact()?;

    let default_stats_interval = resolve_stats_interval(base.stats_interval, extreme);
    let stats_interval: u64 = Input::with_theme(&theme)
        .with_prompt("Stats interval (seconds, 0=off) · 统计打印间隔(秒, 0关闭)")
        .default(default_stats_interval)
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
    } else {
        None
    };

    base.pattern = Some(pattern.trim().to_string());
    base.mode = mode;
    base.threads = Some(threads);
    base.limit = limit;
    base.out = out;
    base.case_insensitive = case_insensitive;
    base.case_sensitive = !case_insensitive;
    base.print_only = print_only;
    base.stats_interval = Some(stats_interval);
    base.export_ipfs = export_ipfs;
    base.key_name = key_name;
    base.extreme = extreme;
    let use_color = Confirm::with_theme(&theme)
        .with_prompt("Highlight matches? · 高亮显示匹配?")
        .default(!base.no_color)
        .interact()?;
    base.no_color = !use_color;
    base.interactive = false;
    Ok(base)
}

fn preprocess_args(args: &mut Args) -> Result<()> {
    if args.extreme {
        if args.case_insensitive {
            eprintln!(
                "Extreme mode ignores --case-insensitive and forces case-sensitive matching · 极致模式会忽略 --case-insensitive 并强制大小写敏感匹配"
            );
        }
        args.case_insensitive = false;
        args.case_sensitive = true;
    }

    args.stats_interval = Some(resolve_stats_interval(args.stats_interval, args.extreme));

    let raw = args
        .pattern
        .clone()
        .context("pattern required · 需要提供匹配子串")?;
    let mut pattern = raw.trim().to_string();
    if pattern.is_empty() {
        bail!("Pattern cannot be empty · 匹配子串不能为空");
    }
    validate_base58_pattern(&pattern)?;

    if matches!(args.mode, Mode::Prefix) {
        let normalized = normalize_prefix_pattern(&pattern);
        if normalized != pattern {
            eprintln!(
                "Prefix mode requires pattern to start with {REQUIRED_PREFIX}; auto-completed · 前缀匹配要求以 {REQUIRED_PREFIX} 开头，已自动补齐: '{pattern}' -> '{normalized}'"
            );
            pattern = normalized;
        }
    }

    args.pattern = Some(pattern);
    Ok(())
}

fn validate_base58_pattern(pattern: &str) -> Result<()> {
    let mut invalid = Vec::new();
    for ch in pattern.chars() {
        if !BASE58BTC_ALPHABET.contains(ch) && !invalid.contains(&ch) {
            invalid.push(ch);
        }
    }
    if invalid.is_empty() {
        return Ok(());
    }

    let invalid_list = invalid
        .iter()
        .map(|c| format!("'{}'", c))
        .collect::<Vec<_>>()
        .join(", ");

    let mut hints = Vec::new();
    if invalid.contains(&'0') {
        hints.push("`0` (zero) is excluded; use `o` or `O` only when intended · `0`（数字零）不在 Base58 中");
    }
    if invalid.contains(&'O') {
        hints.push("`O` (capital o) is excluded to avoid confusion with `0` · `O`（大写字母 O）不在 Base58 中");
    }
    if invalid.contains(&'I') {
        hints.push("`I` (capital i) is excluded to avoid confusion with `1`/`l` · `I`（大写字母 I）不在 Base58 中");
    }
    if invalid.contains(&'l') {
        hints.push("`l` (lowercase L) is excluded to avoid confusion with `1`/`I` · `l`（小写字母 l）不在 Base58 中");
    }
    if hints.is_empty() {
        hints.push("Use only Base58btc characters: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz · 仅可使用 Base58btc 字符集");
    }

    bail!(
        "Invalid Base58 pattern: illegal character(s) {invalid_list} · Base58 模式非法字符: {invalid_list}\n{}",
        hints.join("\n")
    );
}

fn normalize_prefix_pattern(pattern: &str) -> String {
    if pattern.starts_with(REQUIRED_PREFIX) {
        return pattern.to_string();
    }

    let required_lower = REQUIRED_PREFIX.to_ascii_lowercase();
    let pattern_lower = pattern.to_ascii_lowercase();

    if pattern_lower.starts_with(&required_lower) && pattern.len() >= REQUIRED_PREFIX.len() {
        let suffix = &pattern[REQUIRED_PREFIX.len()..];
        return format!("{REQUIRED_PREFIX}{suffix}");
    }

    if required_lower.starts_with(&pattern_lower) {
        return REQUIRED_PREFIX.to_string();
    }

    format!("{REQUIRED_PREFIX}{pattern}")
}

fn resolve_effective_limit(limit: Option<usize>) -> Option<usize> {
    match limit {
        None => Some(10),
        Some(0) => None,
        Some(n) => Some(n),
    }
}

fn resolve_stats_interval(stats_interval: Option<u64>, extreme: bool) -> u64 {
    match stats_interval {
        Some(v) => v,
        None => {
            if extreme {
                1
            } else {
                2
            }
        }
    }
}

fn effective_case_insensitive(args: &Args) -> bool {
    if args.case_sensitive {
        false
    } else if args.case_insensitive {
        true
    } else {
        true
    }
}

fn mode_as_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Any => "any",
        Mode::Prefix => "prefix",
        Mode::Suffix => "suffix",
    }
}

fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn build_equivalent_command(args: &Args) -> String {
    let mut parts = Vec::new();
    parts.push("kooforge".to_string());
    let pattern = args
        .pattern
        .as_ref()
        .expect("pattern required for command preview");
    parts.push(shell_quote(pattern));
    parts.push(format!("--mode {}", mode_as_str(args.mode)));
    parts.push(format!(
        "--threads {}",
        args.threads.unwrap_or_else(num_cpus::get)
    ));
    match resolve_effective_limit(args.limit) {
        Some(n) => parts.push(format!("--limit {n}")),
        None => parts.push("--limit 0".to_string()),
    }
    parts.push(format!(
        "--out {}",
        shell_quote(&args.out.display().to_string())
    ));
    if effective_case_insensitive(args) {
        parts.push("--case-insensitive".to_string());
    } else {
        parts.push("--case-sensitive".to_string());
    }
    if args.print_only {
        parts.push("--print-only".to_string());
    }
    if args.export_ipfs {
        parts.push("--export-ipfs".to_string());
        if let Some(name) = &args.key_name {
            parts.push(format!("--key-name {}", shell_quote(name)));
        }
    }
    if args.no_color {
        parts.push("--no-color".to_string());
    }
    if args.extreme {
        parts.push("--extreme".to_string());
    }
    parts.push(format!(
        "--stats-interval {}",
        resolve_stats_interval(args.stats_interval, args.extreme)
    ));
    parts.join(" ")
}

type MatchFn = fn(&[u8], &[u8]) -> bool;

#[derive(Clone)]
struct Matcher {
    needle: Vec<u8>,
    match_fn: MatchFn,
}

impl Matcher {
    fn new(mode: Mode, case_insensitive: bool, pattern: &str) -> Self {
        let needle = if case_insensitive {
            ascii_lowercase_bytes(pattern.as_bytes())
        } else {
            pattern.as_bytes().to_vec()
        };

        let match_fn = match (mode, case_insensitive) {
            (Mode::Any, false) => contains_cs,
            (Mode::Prefix, false) => starts_with_cs,
            (Mode::Suffix, false) => ends_with_cs,
            (Mode::Any, true) => contains_ci,
            (Mode::Prefix, true) => starts_with_ci,
            (Mode::Suffix, true) => ends_with_ci,
        };

        Self { needle, match_fn }
    }

    #[inline]
    fn is_match(&self, hay: &[u8]) -> bool {
        (self.match_fn)(hay, &self.needle)
    }
}

fn worker_loop_standard(
    tx: Sender<Hit>,
    stop: Arc<AtomicBool>,
    matcher: Matcher,
    print_only: bool,
    total_attempts: Arc<AtomicU64>,
) {
    let mut rng = init_thread_rng();
    let mut pid_b58_buf = Vec::with_capacity(64);

    while !stop.load(Ordering::Relaxed) {
        total_attempts.fetch_add(1, Ordering::Relaxed);
        let sk = SigningKey::generate(&mut rng);
        let kp = keypair_from_signing_key(&sk);
        let pid = PeerId::from_public_key(&kp.public());

        pid_b58_buf.clear();
        bs58::encode(pid.to_bytes())
            .onto(&mut pid_b58_buf)
            .expect("base58 encode failed · Base58 编码失败");

        if matcher.is_match(&pid_b58_buf) {
            let peer_id_b58 = String::from_utf8(pid_b58_buf.clone())
                .expect("base58 output must be utf8 · Base58 输出必须是 UTF-8");
            let sk_protobuf = if print_only {
                None
            } else {
                encode_private_key_protobuf(&kp).ok()
            };
            let _ = tx.send(Hit {
                peer_id_b58,
                sk_protobuf,
            });
        }
    }
}

fn worker_loop_extreme(
    tx: Sender<Hit>,
    stop: Arc<AtomicBool>,
    matcher: Matcher,
    print_only: bool,
    total_attempts: Arc<AtomicU64>,
) {
    let mut rng = init_thread_rng();
    let mut peer_id_raw = [0u8; 38];
    peer_id_raw[..ED25519_PEER_ID_MULTIHASH_PREFIX.len()]
        .copy_from_slice(&ED25519_PEER_ID_MULTIHASH_PREFIX);
    let mut pid_b58_buf = Vec::with_capacity(64);

    while !stop.load(Ordering::Relaxed) {
        total_attempts.fetch_add(1, Ordering::Relaxed);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        peer_id_raw[ED25519_PEER_ID_MULTIHASH_PREFIX.len()..].copy_from_slice(vk.as_bytes());

        pid_b58_buf.clear();
        bs58::encode(peer_id_raw)
            .onto(&mut pid_b58_buf)
            .expect("base58 encode failed · Base58 编码失败");

        if matcher.is_match(&pid_b58_buf) {
            let peer_id_b58 = String::from_utf8(pid_b58_buf.clone())
                .expect("base58 output must be utf8 · Base58 输出必须是 UTF-8");
            let sk_protobuf = if print_only {
                None
            } else {
                let kp = keypair_from_signing_key(&sk);
                encode_private_key_protobuf(&kp).ok()
            };
            let _ = tx.send(Hit {
                peer_id_b58,
                sk_protobuf,
            });
        }
    }
}

fn init_thread_rng() -> StdRng {
    StdRng::from_rng(&mut OsRng).expect("failed to initialize thread RNG · 线程 RNG 初始化失败")
}

fn keypair_from_signing_key(sk: &SigningKey) -> Keypair {
    let vk = sk.verifying_key();
    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(&sk.to_bytes());
    kp_bytes[32..].copy_from_slice(vk.as_bytes());
    let ed = ed25519::Keypair::try_from_bytes(&mut kp_bytes)
        .expect("ed25519 key compose · 组装 ed25519 密钥失败");
    Keypair::from(ed)
}

#[inline]
fn ascii_lower_byte(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

fn ascii_lowercase_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().map(|&b| ascii_lower_byte(b)).collect()
}

fn contains_cs(hay: &[u8], needle: &[u8]) -> bool {
    memmem::find(hay, needle).is_some()
}

fn starts_with_cs(hay: &[u8], needle: &[u8]) -> bool {
    hay.starts_with(needle)
}

fn ends_with_cs(hay: &[u8], needle: &[u8]) -> bool {
    hay.ends_with(needle)
}

fn starts_with_ci(hay: &[u8], needle_lower: &[u8]) -> bool {
    if hay.len() < needle_lower.len() {
        return false;
    }
    for (h, n) in hay.iter().zip(needle_lower.iter()) {
        if ascii_lower_byte(*h) != *n {
            return false;
        }
    }
    true
}

fn ends_with_ci(hay: &[u8], needle_lower: &[u8]) -> bool {
    if hay.len() < needle_lower.len() {
        return false;
    }
    let offset = hay.len() - needle_lower.len();
    for i in 0..needle_lower.len() {
        if ascii_lower_byte(hay[offset + i]) != needle_lower[i] {
            return false;
        }
    }
    true
}

fn contains_ci(hay: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if hay.len() < needle_lower.len() {
        return false;
    }

    let max_start = hay.len() - needle_lower.len();
    let first = needle_lower[0];
    let mut i = 0usize;
    while i <= max_start {
        if ascii_lower_byte(hay[i]) == first {
            let mut j = 1usize;
            while j < needle_lower.len() && ascii_lower_byte(hay[i + j]) == needle_lower[j] {
                j += 1;
            }
            if j == needle_lower.len() {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn aggregator(
    rx: Receiver<Hit>,
    args: &Args,
    stop: Arc<AtomicBool>,
    pat: &str,
    eff_limit: Option<usize>,
    ci: bool,
    stats_interval: u64,
    total_attempts: Arc<AtomicU64>,
) -> Result<()> {
    let mut found = 0usize;
    let mut last_stats = OffsetDateTime::now_utc();
    let mut last_attempts = 0u64;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(hit) => {
                found += 1;
                let out = if args.no_color {
                    hit.peer_id_b58.clone()
                } else {
                    highlight(&hit.peer_id_b58, pat, args.mode, ci)
                };
                println!("{}", out);
                if let Some(sk) = hit.sk_protobuf {
                    write_key(&args.out, &hit.peer_id_b58, &sk)?;
                    if args.export_ipfs {
                        if let Some(name) = &args.key_name {
                            write_named_key(&args.out, name, &sk)?;
                        }
                    }
                }
                if let Some(limit) = eff_limit {
                    if found >= limit {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }

        if stats_interval > 0 {
            let now = OffsetDateTime::now_utc();
            let secs = (now - last_stats).whole_seconds();
            if secs >= stats_interval as i64 {
                let current_attempts = total_attempts.load(Ordering::Relaxed);
                let attempts_diff = current_attempts - last_attempts;
                let rate = if secs > 0 {
                    attempts_diff as f64 / secs as f64
                } else {
                    0.0
                };
                println!("[stats 统计 {}] hits/命中={}, processed/已处理={}, rate/效率={:.0}/s, threads/线程={}, mode/模式={:?}", now.format(&Rfc3339)?, found, current_attempts, rate, args.threads.unwrap_or_else(num_cpus::get), args.mode);
                last_stats = now;
                last_attempts = current_attempts;
            }
        }
    }

    Ok(())
}

fn write_key(out_dir: &Path, peer_id_b58: &str, sk_protobuf: &[u8]) -> Result<()> {
    let key_path = out_dir.join(peer_id_b58);
    let tmp = out_dir.join(format!("{}.tmp", peer_id_b58));
    {
        let mut f = File::create(&tmp).with_context(|| {
            format!(
                "Failed to create temp file: {} · 创建临时文件失败: {}",
                tmp.display(),
                tmp.display()
            )
        })?;
        f.write_all(sk_protobuf)?;
        f.flush()?;
    }
    fs::rename(&tmp, &key_path).with_context(|| {
        format!(
            "Atomic rename failed: {} · 原子重命名失败: {}",
            key_path.display(),
            key_path.display()
        )
    })?;

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
        let mut f = File::create(&tmp).with_context(|| {
            format!(
                "Failed to create temp file: {} · 创建临时文件失败: {}",
                tmp.display(),
                tmp.display()
            )
        })?;
        f.write_all(sk_protobuf)?;
        f.flush()?;
    }
    fs::rename(&tmp, &key_path).with_context(|| {
        format!(
            "Atomic rename failed: {} · 原子重命名失败: {}",
            key_path.display(),
            key_path.display()
        )
    })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn base_args() -> Args {
        Args {
            pattern: Some("12D3KooWabc".to_string()),
            mode: Mode::Prefix,
            threads: Some(8),
            limit: Some(0),
            out: PathBuf::from("keystore dir"),
            case_insensitive: false,
            case_sensitive: true,
            print_only: true,
            stats_interval: Some(1),
            key_name: Some("dupa key".to_string()),
            export_ipfs: true,
            interactive: false,
            no_color: true,
            extreme: false,
        }
    }

    #[test]
    fn base58_accepts_valid_characters() {
        let all = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        assert!(validate_base58_pattern(all).is_ok());
    }

    #[test]
    fn base58_rejects_confusing_characters() {
        for ch in ['0', 'O', 'I', 'l'] {
            let err = validate_base58_pattern(&format!("A{ch}B"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(&format!("'{ch}'")));
        }
    }

    #[test]
    fn prefix_normalization_keeps_valid_pattern() {
        assert_eq!(normalize_prefix_pattern("12D3KooWabc"), "12D3KooWabc");
    }

    #[test]
    fn prefix_normalization_completes_partial_prefix() {
        assert_eq!(normalize_prefix_pattern("12D3"), "12D3KooW");
    }

    #[test]
    fn prefix_normalization_prepends_missing_prefix() {
        assert_eq!(normalize_prefix_pattern("abc"), "12D3KooWabc");
    }

    #[test]
    fn prefix_normalization_canonicalizes_prefix_case() {
        assert_eq!(normalize_prefix_pattern("12d3koowX"), "12D3KooWX");
    }

    #[test]
    fn resolve_limit_semantics() {
        assert_eq!(resolve_effective_limit(None), Some(10));
        assert_eq!(resolve_effective_limit(Some(0)), None);
        assert_eq!(resolve_effective_limit(Some(5)), Some(5));
    }

    #[test]
    fn build_command_prints_unlimited_as_zero() {
        let args = base_args();
        let cmd = build_equivalent_command(&args);
        assert!(cmd.contains("kooforge 12D3KooWabc"));
        assert!(cmd.contains("--limit 0"));
        assert!(cmd.contains("--case-sensitive"));
        assert!(cmd.contains("--key-name 'dupa key'"));
        assert!(cmd.contains("--stats-interval 1"));
    }

    #[test]
    fn build_command_prints_extreme_flag() {
        let mut args = base_args();
        args.extreme = true;
        args.stats_interval = None;
        let cmd = build_equivalent_command(&args);
        assert!(cmd.contains("--extreme"));
        assert!(cmd.contains("--stats-interval 1"));
    }

    #[test]
    fn resolve_stats_interval_semantics() {
        assert_eq!(resolve_stats_interval(None, false), 2);
        assert_eq!(resolve_stats_interval(None, true), 1);
        assert_eq!(resolve_stats_interval(Some(7), false), 7);
        assert_eq!(resolve_stats_interval(Some(7), true), 7);
    }

    #[test]
    fn matcher_case_sensitive_behaviour() {
        let any = Matcher::new(Mode::Any, false, "aB");
        let prefix = Matcher::new(Mode::Prefix, false, "aB");
        let suffix = Matcher::new(Mode::Suffix, false, "aB");

        assert!(any.is_match(b"xxaByy"));
        assert!(!any.is_match(b"xxAByy"));
        assert!(prefix.is_match(b"aBzzz"));
        assert!(!prefix.is_match(b"ABzzz"));
        assert!(suffix.is_match(b"zzzaB"));
        assert!(!suffix.is_match(b"zzzAB"));
    }

    #[test]
    fn matcher_case_insensitive_behaviour() {
        let any = Matcher::new(Mode::Any, true, "aB");
        let prefix = Matcher::new(Mode::Prefix, true, "aB");
        let suffix = Matcher::new(Mode::Suffix, true, "aB");

        assert!(any.is_match(b"xxAByy"));
        assert!(prefix.is_match(b"ABzzz"));
        assert!(suffix.is_match(b"zzzAB"));
    }

    #[test]
    fn preprocess_extreme_forces_case_sensitive() {
        let mut args = base_args();
        args.extreme = true;
        args.case_insensitive = true;
        args.case_sensitive = false;
        args.stats_interval = None;
        preprocess_args(&mut args).expect("preprocess must pass");

        assert!(args.case_sensitive);
        assert!(!args.case_insensitive);
        assert_eq!(args.stats_interval, Some(1));
    }

    #[test]
    fn extreme_peer_id_encoding_matches_libp2p_for_random_keys() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut peer_id_raw = [0u8; 38];
        peer_id_raw[..ED25519_PEER_ID_MULTIHASH_PREFIX.len()]
            .copy_from_slice(&ED25519_PEER_ID_MULTIHASH_PREFIX);
        let mut fast_buf = Vec::with_capacity(64);

        for _ in 0..1000 {
            let sk = SigningKey::generate(&mut rng);
            let vk = sk.verifying_key();

            let kp = keypair_from_signing_key(&sk);
            let std_pid =
                bs58::encode(PeerId::from_public_key(&kp.public()).to_bytes()).into_string();

            peer_id_raw[ED25519_PEER_ID_MULTIHASH_PREFIX.len()..].copy_from_slice(vk.as_bytes());
            fast_buf.clear();
            bs58::encode(peer_id_raw)
                .onto(&mut fast_buf)
                .expect("fast base58 encode failed");
            let fast_pid = String::from_utf8(fast_buf.clone()).expect("utf8");

            assert_eq!(fast_pid, std_pid);
        }
    }

    #[test]
    fn protobuf_roundtrip_compatible_for_hit_path() {
        let mut rng = StdRng::seed_from_u64(11);
        for _ in 0..128 {
            let sk = SigningKey::generate(&mut rng);
            let kp = keypair_from_signing_key(&sk);
            let encoded = encode_private_key_protobuf(&kp).expect("encode");
            let decoded = Keypair::from_protobuf_encoding(&encoded).expect("decode");
            assert_eq!(kp.public(), decoded.public());
        }
    }
}
