//! worker.rs — Wisp-CF: Wisp v1.2 server for Cloudflare Workers (Rust → wasm).
//!
//! Inbound: WSS only (one Wisp packet per WebSocket binary message, original v1.2 layout).
//! Outbound: raw TCP via `connect()` (SecureTransport::Off) and HTTP via `fetch()` GET/HEAD.
//! UDP removed (CONNECT type 0x02 → CLOSE 0x41). Queue + scheduler + egress hub as per protocol.md.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll, Waker};

use worker::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
type WResult<T> = std::result::Result<T, worker::Error>;

// ---------------------------------------------------------------------------
// §1 Config
// ---------------------------------------------------------------------------

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EMPTY_EXTRAS: [(&str, &str); 0] = [];
const SLOT_CEILING: u32 = 6;

#[derive(Clone)]
struct Config {
    wisp_path: String,
    wisp_secret: Option<String>,
    allowed_origins: Vec<String>,
    // slots & queue
    head_slots: u32,
    tcp_slots: u32,
    queue_max: u32,
    queue_wait_ms: u64,
    max_open_streams: u32,
    subrequest_max: u32,
    rotate_on_budget: bool,
    drain_ms: u64,
    // session & packets
    buffer_size: u32,
    max_frame_bytes: u64,
    data_chunk: u32,
    session_max_ms: u64,
    stream_idle_ms: u64,
    stream_max_ms: u64,
    connect_timeout_ms: u64,
    // egress hub
    stream_out_cap: u64,
    egress_cap: u64,
    egress_rate_bps: u64,
    stream_max_bytes: u64,
    // http lane
    http_lane_ports: Vec<u16>,
    http_lane_methods: Vec<String>,
    http_head_max: u32,
    max_body_bytes: u32,
    head_max_bytes: u64,
    head_timeout_ms: u64,
    lane_fallback: LaneFallback,
    parallel_ranges: bool,
    split_threshold: u64,
    split_chunk: u64,
    // policy
    allow_hosts: Vec<String>,
    block_hosts: Vec<String>,
    self_host: String,
}

#[derive(Clone, Copy, PartialEq)]
enum LaneFallback {
    Tcp,
    Reject,
}

fn get_var(env: &Env, name: &str) -> Option<String> {
    env.var(name).ok().map(|v| v.to_string())
}

fn parse_bool(s: Option<String>) -> Option<bool> {
    s?.to_lowercase().parse::<bool>().ok()
}

impl Config {
    fn from_env(env: &Env) -> Self {
        let self_host = get_var(env, "SELF_HOST").unwrap_or_default().to_lowercase();
        let mut cfg = Config {
            wisp_path: get_var(env, "WISP_PATH").unwrap_or_else(|| "/wisp/".into()),
            wisp_secret: get_var(env, "WISP_SECRET"),
            allowed_origins: get_var(env, "ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            head_slots: get_var(env, "HEAD_SLOTS").and_then(|v| v.parse().ok()).unwrap_or(4),
            tcp_slots: get_var(env, "TCP_SLOTS").and_then(|v| v.parse().ok()).unwrap_or(2),
            queue_max: get_var(env, "QUEUE_MAX").and_then(|v| v.parse().ok()).unwrap_or(64),
            queue_wait_ms: get_var(env, "QUEUE_WAIT_MS").and_then(|v| v.parse().ok()).unwrap_or(10_000),
            max_open_streams: get_var(env, "MAX_OPEN_STREAMS").and_then(|v| v.parse().ok()).unwrap_or(64),
            subrequest_max: get_var(env, "SUBREQUEST_MAX").and_then(|v| v.parse().ok()).unwrap_or(45),
            rotate_on_budget: parse_bool(get_var(env, "ROTATE_ON_BUDGET")).unwrap_or(true),
            drain_ms: get_var(env, "DRAIN_MS").and_then(|v| v.parse().ok()).unwrap_or(5_000),
            buffer_size: get_var(env, "BUFFER_SIZE").and_then(|v| v.parse().ok()).unwrap_or(128),
            max_frame_bytes: get_var(env, "MAX_FRAME_BYTES").and_then(|v| v.parse().ok()).unwrap_or(1_048_576),
            data_chunk: get_var(env, "DATA_CHUNK").and_then(|v| v.parse().ok()).unwrap_or(16_384),
            session_max_ms: get_var(env, "SESSION_MAX_MS").and_then(|v| v.parse().ok()).unwrap_or(0),
            stream_idle_ms: get_var(env, "STREAM_IDLE_MS").and_then(|v| v.parse().ok()).unwrap_or(15_000),
            stream_max_ms: get_var(env, "STREAM_MAX_MS").and_then(|v| v.parse().ok()).unwrap_or(60_000),
            connect_timeout_ms: get_var(env, "CONNECT_TIMEOUT_MS").and_then(|v| v.parse().ok()).unwrap_or(8_000),
            stream_out_cap: get_var(env, "STREAM_OUT_CAP").and_then(|v| v.parse().ok()).unwrap_or(1_048_576),
            egress_cap: get_var(env, "EGRESS_CAP").and_then(|v| v.parse().ok()).unwrap_or(8_388_608),
            egress_rate_bps: get_var(env, "EGRESS_RATE_BPS").and_then(|v| v.parse().ok()).unwrap_or(0),
            stream_max_bytes: get_var(env, "STREAM_MAX_BYTES").and_then(|v| v.parse().ok()).unwrap_or(0),
            http_lane_ports: get_var(env, "HTTP_LANE_PORTS")
                .unwrap_or_else(|| "80,443".into())
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect(),
            http_lane_methods: get_var(env, "HTTP_LANE_METHODS")
                .unwrap_or_else(|| "GET,HEAD".into())
                .split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect(),
            http_head_max: get_var(env, "HTTP_HEAD_MAX").and_then(|v| v.parse().ok()).unwrap_or(65_536),
            max_body_bytes: get_var(env, "MAX_BODY_BYTES").and_then(|v| v.parse().ok()).unwrap_or(1_048_576),
            head_max_bytes: get_var(env, "HEAD_MAX_BYTES").and_then(|v| v.parse().ok()).unwrap_or(33_554_432),
            head_timeout_ms: get_var(env, "HEAD_TIMEOUT_MS").and_then(|v| v.parse().ok()).unwrap_or(15_000),
            lane_fallback: match get_var(env, "LANE_FALLBACK").as_deref().map(str::trim) {
                Some("reject") => LaneFallback::Reject,
                _ => LaneFallback::Tcp,
            },
            parallel_ranges: parse_bool(get_var(env, "PARALLEL_RANGES")).unwrap_or(false),
            split_threshold: get_var(env, "SPLIT_THRESHOLD").and_then(|v| v.parse().ok()).unwrap_or(4_194_304),
            split_chunk: get_var(env, "SPLIT_CHUNK").and_then(|v| v.parse().ok()).unwrap_or(2_097_152),
            allow_hosts: get_var(env, "ALLOW_HOSTS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            block_hosts: get_var(env, "BLOCK_HOSTS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            self_host,
        };
        // §5 clamps: HEAD_SLOTS + TCP_SLOTS ≤ 6 (reduce TCP first, then heads, keep ≥1 each)
        if cfg.head_slots + cfg.tcp_slots > SLOT_CEILING {
            let excess = cfg.head_slots + cfg.tcp_slots - SLOT_CEILING;
            let cut_tcp = cfg.tcp_slots.saturating_sub(excess).max(1);
            let excess = excess - (cfg.tcp_slots - cut_tcp);
            cfg.tcp_slots = cut_tcp;
            cfg.head_slots = (cfg.head_slots.saturating_sub(excess)).max(1);
        }
        cfg.buffer_size = cfg.buffer_size.max(2);
        cfg.queue_max = cfg.queue_max.max(1);
        cfg.data_chunk = cfg.data_chunk.clamp(1024, 65_536);
        cfg.max_frame_bytes = cfg.max_frame_bytes.min(33_554_432);
        cfg
    }
}

fn now_ms() -> u64 {
    worker::Date::now().as_millis()
}

// ---------------------------------------------------------------------------
// §2 Packet codec — one Wisp packet per WebSocket binary message, little-endian
// ---------------------------------------------------------------------------

const T_CONNECT: u8 = 0x01;
const T_DATA: u8 = 0x02;
const T_CONTINUE: u8 = 0x03;
const T_CLOSE: u8 = 0x04;

const CR_UNSPECIFIED: u8 = 0x01;
const CR_VOLUNTARY: u8 = 0x02;
const CR_NET_ERROR: u8 = 0x03;
const CR_INVALID: u8 = 0x41;
const CR_UNREACHABLE: u8 = 0x42;
const CR_TIMEOUT: u8 = 0x43;
const CR_REFUSED: u8 = 0x44;
const CR_CUT: u8 = 0x47;
const CR_BLOCKED: u8 = 0x48;
const CR_THROTTLED: u8 = 0x49;

struct Packet<'a> {
    t: u8,
    sid: u32,
    payload: &'a [u8],
}

fn parse_packet(m: &[u8]) -> Option<Packet<'_>> {
    if m.len() < 5 {
        return None;
    }
    Some(Packet {
        t: m[0],
        sid: u32::from_le_bytes([m[1], m[2], m[3], m[4]]),
        payload: &m[5..],
    })
}

fn continue_packet(sid: u32, remaining: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    v.push(T_CONTINUE);
    v.extend_from_slice(&sid.to_le_bytes());
    v.extend_from_slice(&remaining.to_le_bytes());
    v
}

fn close_packet(sid: u32, reason: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(6);
    v.push(T_CLOSE);
    v.extend_from_slice(&sid.to_le_bytes());
    v.push(reason);
    v
}

fn data_packet(sid: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.push(T_DATA);
    v.extend_from_slice(&sid.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

// ---------------------------------------------------------------------------
// §3 Destination policy
// ---------------------------------------------------------------------------

fn is_private_v4(octets: [u8; 4]) -> bool {
    let [a, b, _, _] = octets;
    a == 127 // loopback 127/8
        || a == 10 // 10/8
        || (a == 172 && (16..=31).contains(&b)) // 172.16/12
        || (a == 192 && b == 168) // 192.168/16
        || (a == 169 && b == 254) // link-local
        || (a == 100 && (64..=127).contains(&b)) // CGNAT 100.64/10
        || a == 0 // 0/8 "this" network
        || (a == 192 && b == 0) // 192.0.0/24 incl. 192.0.2 test
        || (a == 198 && (18..=19).contains(&b)) // benchmarking 198.18/15
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let s = s.trim();
    let mut out = [0u8; 4];
    let mut it = s.split('.');
    for slot in out.iter_mut() {
        let part = it.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        *slot = v as u8;
    }
    if it.next().is_some() {
        return None;
    }
    Some(out)
}

fn parse_ipv6(s: &str) -> Option<[u16; 8]> {
    let s = s.trim();
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let mut left: Vec<u16> = Vec::new();
    if !head.is_empty() {
        for part in head.split(':') {
            left.push(u16::from_str_radix(part, 16).ok()?);
        }
    }
    let mut right: Vec<u16> = Vec::new();
    if let Some(t) = tail {
        if !t.is_empty() {
            for part in t.split(':') {
                right.push(u16::from_str_radix(part, 16).ok()?);
            }
        }
    }
    if tail.is_none() && left.len() != 8 {
        return None;
    }
    if tail.is_some() && left.len() + right.len() > 7 {
        return None;
    }
    let mut out = [0u16; 8];
    out[..left.len()].copy_from_slice(&left);
    out[8 - right.len()..].copy_from_slice(&right);
    Some(out)
}

fn ipv6_is_private(groups: &[u16; 8]) -> bool {
    let g0 = groups[0];
    let g1 = groups[1];
    // ::1 loopback
    let is_loopback = groups[..7].iter().all(|&g| g == 0) && groups[7] == 1;
    // fc00::/7 unique local
    let is_unique_local = (g0 & 0xFE00) == 0xFC00;
    // fe80::/10 link-local
    let is_link_local = (g0 & 0xFFC0) == 0xFE80;
    // IPv4-mapped private ::ffff:a.b.c.d
    let is_mapped_private = groups[..5].iter().all(|&g| g == 0)
        && groups[5] == 0xFFFF
        && is_private_v4([(g0 >> 8) as u8, g0 as u8, (g1 >> 8) as u8, g1 as u8]);
    is_loopback || is_unique_local || is_link_local || is_mapped_private
}

fn check_target(cfg: &Config, host_raw: &[u8], port: u16) -> std::result::Result<(), u8> {
    if host_raw.is_empty() || host_raw.len() > 253 {
        return Err(CR_INVALID);
    }
    let host = String::from_utf8_lossy(host_raw).trim().to_lowercase();
    if port == 0 {
        return Err(CR_INVALID);
    }
    if port == 25 {
        return Err(CR_BLOCKED);
    }
    // IP literal checks
    if let Some(v4) = parse_ipv4(&host) {
        if is_private_v4(v4) {
            return Err(CR_BLOCKED);
        }
        return Ok(());
    }
    let v6_candidate = host.trim_start_matches('[').trim_end_matches(']');
    if let Some(v6) = parse_ipv6(v6_candidate) {
        if ipv6_is_private(&v6) {
            return Err(CR_BLOCKED);
        }
        return Ok(());
    }
    if v6_candidate.contains(':') && !v6_candidate.is_empty() {
        // looked like v6 but did not parse
        return Err(CR_INVALID);
    }
    // name checks
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(CR_BLOCKED);
    }
    // self hostname (loop protection)
    if !cfg.self_host.is_empty() && host == cfg.self_host {
        return Err(CR_BLOCKED);
    }
    // allow list (suffix match)
    if !cfg.allow_hosts.is_empty() {
        let ok = cfg
            .allow_hosts
            .iter()
            .any(|a| host == *a || host.ends_with(&format!(".{a}")));
        if !ok {
            return Err(CR_BLOCKED);
        }
    }
    // block list (suffix match)
    if cfg
        .block_hosts
        .iter()
        .any(|b| host == *b || host.ends_with(&format!(".{b}")))
    {
        return Err(CR_BLOCKED);
    }
    Ok(())
}

/// Constant-time comparison of two secrets.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// §4 HTTP request parser (strict, incremental, bounded) + TLS sniff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum HttpReject {
    BadRequest,   // 400
    HeadTooLarge, // 431
    MethodNotAllowed,
    UpgradeAttempt, // 501
}

struct ParsedRequest {
    method: String,
    path_and_query: String,
    headers: Vec<(String, String)>,
}

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn looks_like_http_request_line(buf: &[u8]) -> bool {
    // Sniff: `METHOD SP ...` with an uppercase A-Z token. Origin-form is enforced later by
    // the strict parser (absolute-form → 400); non-HTTP bytes (incl. TLS records, handled
    // separately) fall through to the lane fallback.
    let sp = match buf.iter().position(|&b| b == b' ') {
        Some(i) if (1..=32).contains(&i) => i,
        _ => return false,
    };
    if !buf[..sp].iter().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    matches!(buf.get(sp + 1), Some(c) if c.is_ascii_graphic())
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn has_bare_lf(head: &[u8]) -> bool {
    // any \n that is not preceded by \r
    for (i, &b) in head.iter().enumerate() {
        if b == b'\n' && (i == 0 || head[i - 1] != b'\r') {
            return true;
        }
    }
    false
}

fn parse_http_head(buf: &[u8], cfg: &Config) -> std::result::Result<ParsedRequest, HttpReject> {
    let end = match find_crlfcrlf(buf) {
        Some(e) => e,
        None => return Err(HttpReject::BadRequest),
    };
    let head = &buf[..end]; // request line + header lines, without the blank line
    if buf.contains(&0u8) {
        return Err(HttpReject::BadRequest);
    }
    if has_bare_lf(head) {
        return Err(HttpReject::BadRequest);
    }
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line = lines.next().unwrap_or(&b""[..]);
    let rl = String::from_utf8_lossy(request_line).to_string();
    let mut parts = rl.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() || parts.next().is_some() {
        return Err(HttpReject::BadRequest);
    }
    if !version.starts_with("HTTP/1.") {
        return Err(HttpReject::BadRequest);
    }
    if !target.starts_with('/') {
        return Err(HttpReject::BadRequest); // origin-form required (absolute-form rejected)
    }
    if method.eq_ignore_ascii_case("connect") {
        return Err(HttpReject::BadRequest);
    }
    // headers
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut saw_fold = false;
    let mut content_length: Option<u64> = None;
    let mut saw_te = false;
    let mut upgrade = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            saw_fold = true; // obsolete line folding
            continue;
        }
        let (name_raw, value_raw) = match line.iter().position(|&b| b == b':') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => return Err(HttpReject::BadRequest),
        };
        let name = String::from_utf8_lossy(name_raw).to_lowercase();
        let value = String::from_utf8_lossy(value_raw).trim().to_string();
        if name.is_empty()
            || name
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err(HttpReject::BadRequest);
        }
        if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(HttpReject::BadRequest); // control characters in values
        }
        match name.as_str() {
            "content-length" => {
                let v: u64 = match value.parse() {
                    Ok(v) => v,
                    Err(_) => return Err(HttpReject::BadRequest),
                };
                if content_length.is_some() && content_length != Some(v) {
                    return Err(HttpReject::BadRequest); // duplicate/conflicting
                }
                content_length = Some(v);
            }
            "transfer-encoding" => saw_te = true,
            "upgrade" => upgrade = true,
            _ => {}
        }
        headers.push((name, value));
    }
    if saw_fold {
        return Err(HttpReject::BadRequest);
    }
    if saw_te && content_length.is_some() {
        return Err(HttpReject::BadRequest); // smuggling hygiene
    }
    if upgrade {
        return Err(HttpReject::UpgradeAttempt);
    }
    if !cfg.http_lane_methods.iter().any(|m| m == &method) {
        return Err(HttpReject::MethodNotAllowed);
    }
    let _ = content_length;
    Ok(ParsedRequest {
        method,
        path_and_query: target,
        headers,
    })
}

/// True when the first bytes look like a TLS record (0x16 0x03 …).
fn is_tls_record(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == 0x16 && buf[1] == 0x03
}

// ---------------------------------------------------------------------------
// §5 Synthetic response builder
// ---------------------------------------------------------------------------

fn sanitize_value(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            '\r' | '\n' | '\u{0}' | '\u{7f}'..='\u{ffff}' => ' ',
            c => c,
        })
        .collect()
}

/// Build the synthetic HTTP/1.1 response head: status line + headers, hop-by-hop stripped,
/// decoded-body header rules, CR/LF sanitising, Connection: close.
fn build_synthetic_head(status: u16, headers: &worker::Headers) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} OK\r\n");
    for (k, v) in headers.entries() {
        let kl = k.to_lowercase();
        if HOP_BY_HOP.contains(&kl.as_str())
            || kl == "content-encoding"
            || kl == "content-length"
            || kl == "transfer-encoding"
            || kl == "set-cookie"
        {
            continue;
        }
        let v = sanitize_value(&v);
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Connection: close\r\n");
    out.push_str("\r\n");
    out.into_bytes()
}

fn build_set_cookie_lines(headers: &worker::Headers) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    for (k, v) in headers.entries() {
        if k.eq_ignore_ascii_case("set-cookie") {
            let v = sanitize_value(&v);
            lines.push(format!("Set-Cookie: {v}\r\n").into_bytes());
        }
    }
    lines
}

fn synthetic_error_response(status: u16, msg: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status} {msg}\r\n");
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    head.push_str("Connection: close\r\n\r\n");
    head.into_bytes()
}

// ---------------------------------------------------------------------------
// §6 Error mapping
// ---------------------------------------------------------------------------

fn map_connect_error(e: &str, open_timeout: bool) -> u8 {
    if open_timeout {
        return CR_TIMEOUT;
    }
    let s = e.to_lowercase();
    if s.contains("proxy request failed") || s.contains("tcp loop") || s.contains("prohibited") {
        return CR_BLOCKED;
    }
    if s.contains("refused") {
        return CR_REFUSED;
    }
    if s.contains("timeout") || s.contains("timed out") {
        return CR_TIMEOUT;
    }
    if s.contains("dns") || s.contains("resolve") || s.contains("getaddrinfo") {
        return CR_UNREACHABLE;
    }
    CR_UNREACHABLE
}

fn map_fetch_error(e: &str, timeout: bool) -> u8 {
    if timeout {
        return CR_TIMEOUT;
    }
    let s = e.to_lowercase();
    if s.contains("dns") || s.contains("resolve") || s.contains("getaddrinfo") {
        return CR_UNREACHABLE;
    }
    if s.contains("refused") {
        return CR_REFUSED;
    }
    if s.contains("timeout") || s.contains("timed out") {
        return CR_TIMEOUT;
    }
    if s.contains("prohibited") || s.contains("blocked") {
        return CR_BLOCKED;
    }
    CR_NET_ERROR
}

// ---------------------------------------------------------------------------
// §7 Stream Table / Job Queue / Scheduler / Executors / Hub / Session
// ---------------------------------------------------------------------------

type Shared<T> = Rc<RefCell<T>>;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Lane {
    Http,
    Tcp,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum StreamPhase {
    Pending, // HTTP lane: waiting for request head / sniff
    Queued,  // waiting for a slot
    Active,  // executor running
    Closed,
}

enum PendingJob {
    TcpConnect { host: String, port: u16, replay: Vec<u8> },
    HttpFetch { url: String, method: String, headers: Vec<(String, String)> },
}

#[derive(Clone)]
struct Job {
    sid: u32,
    lane: Lane,
    inner: Rc<PendingJob>,
    enqueued_ms: u64,
}

#[derive(Clone)]
enum HubEvent {
    Data(u32, Rc<Vec<u8>>),
    Close(u32, u8),
    Continue(u32, u32),
}

struct StreamCtl {
    phase: StreamPhase,
    lane: Lane,
    host: String,
    port: u16,
    rx_fifo: VecDeque<Vec<u8>>, // TCP lane: client DATA buffered
    http_buf: Vec<u8>,          // HTTP lane: request head accumulator
    bytes_in: u64,
    bytes_out: u64,
    opened_ms: u64,
    last_activity_ms: u64,
}

struct SessionState {
    streams: HashMap<u32, StreamCtl>,
    cancelled: bool,
    subrequests: u32,
    queue_high_water: u32,
    rotate_pending: bool,
    total_streams_opened: u32,
}

// --- Notify primitive ------------------------------------------------------

struct NotifyShared {
    waker: Option<Waker>,
    notified: bool,
}

#[derive(Clone)]
struct Notify {
    shared: Rc<RefCell<NotifyShared>>,
}

impl Notify {
    fn new() -> Self {
        Self {
            shared: Rc::new(RefCell::new(NotifyShared { waker: None, notified: false })),
        }
    }
    fn notify(&self) {
        let mut s = self.shared.borrow_mut();
        s.notified = true;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
}

impl Future for Notify {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
        let mut s = self.shared.borrow_mut();
        if s.notified {
            s.notified = false;
            Poll::Ready(())
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// --- NotifyShared with waiting flag for push_await -------------------------

struct HubWaitShared {
    waker: Option<Waker>,
    drained: bool,
}

/// A future that resolves when the hub notifies it (backpressure wait).
struct HubWait {
    shared: Rc<RefCell<HubWaitShared>>,
    hub_notify: Notify,
}

impl Future for HubWait {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
        let mut s = self.shared.borrow_mut();
        if s.drained {
            s.drained = false;
            Poll::Ready(())
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// --- Scheduler -------------------------------------------------------------

struct SchedulerShared {
    active_http: u32,
    active_tcp: u32,
    http_cap: u32,
    tcp_cap: u32,
    queue: VecDeque<Job>,
}

/// A slot permit, released on Drop.
struct SlotPermit {
    lane: Lane,
    release: Option<Box<dyn FnOnce()>>,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

struct Scheduler {
    cfg: Rc<Config>,
    shared: Shared<SchedulerShared>,
    notify: Notify,
    state: Shared<SessionState>,
    hub_tx: Rc<HubTx>,
    ws_closed: Rc<Cell<bool>>,
}

impl Scheduler {
    fn new(cfg: Rc<Config>, state: Shared<SessionState>, hub_tx: Rc<HubTx>, ws_closed: Rc<Cell<bool>>) -> Self {
        Scheduler {
            shared: Rc::new(RefCell::new(SchedulerShared {
                active_http: 0,
                active_tcp: 0,
                http_cap: cfg.head_slots,
                tcp_cap: cfg.tcp_slots,
                queue: VecDeque::new(),
            })),
            cfg,
            notify: Notify::new(),
            state,
            hub_tx,
            ws_closed,
        }
    }

    fn clone_handle(&self) -> Scheduler {
        Scheduler {
            shared: self.shared.clone(),
            notify: self.notify.clone(),
            cfg: self.cfg.clone(),
            state: self.state.clone(),
            hub_tx: self.hub_tx.clone(),
            ws_closed: self.ws_closed.clone(),
        }
    }

    /// Enqueue a job. Returns Err(close_reason) when the queue is full.
    fn enqueue(&self, job: Job) -> std::result::Result<(), u8> {
        {
            let sh = self.shared.borrow();
            if sh.queue.len() as u32 >= self.cfg.queue_max {
                return Err(CR_THROTTLED);
            }
            let mut st = self.state.borrow_mut();
            if sh.queue.len() as u32 > st.queue_high_water {
                st.queue_high_water = sh.queue.len() as u32;
            }
        }
        self.shared.borrow_mut().queue.push_back(job);
        self.notify.notify();
        Ok(())
    }

    /// The dispatch loop: pull jobs when a slot is available.
    async fn run(self) {
        let mut this = self;
        loop {
            let n = this.notify.clone(); n.await;
            if this.state.borrow().cancelled || this.ws_closed.get() {
                return;
            }
            loop {
                let picked = this.pick_job();
                match picked {
                    Some(job) => {
                        let wait_ms = now_ms().saturating_sub(job.enqueued_ms);
                        let expired = wait_ms > this.cfg.queue_wait_ms;
                        let stream_alive = {
                            let st = this.state.borrow();
                            st.streams
                                .get(&job.sid)
                                .map(|s| matches!(s.phase, StreamPhase::Queued | StreamPhase::Active))
                                .unwrap_or(false)
                        };
                        if !stream_alive || expired {
                            if stream_alive {
                                if job.lane == Lane::Http {
                                    this.hub_tx.synthetic_503(job.sid);
                                }
                                this.hub_tx.push(HubEvent::Close(job.sid, if expired { CR_THROTTLED } else { CR_UNSPECIFIED }));
                                mark_closed(&this.state, job.sid);
                            }
                            this.release_slot(job.lane);
                            continue;
                        }
                        let permit = this.make_permit(job.lane);
                        let sched = this.clone_handle();
                        wasm_bindgen_futures::spawn_local(async move {
                            sched.execute(job, permit).await;
                        });
                    }
                    None => break,
                }
            }
        }
    }

    /// Pick the next admissible job and mark its slot active.
    fn pick_job(&self) -> Option<Job> {
        let mut sh = self.shared.borrow_mut();
        let mut idx = 0usize;
        while idx < sh.queue.len() {
            let job = sh.queue[idx].clone();
            let (lane_active, lane_cap, other_queued) = match job.lane {
                Lane::Http => {
                    let other = sh.queue.iter().any(|j| j.lane == Lane::Tcp);
                    (sh.active_http, sh.http_cap, other)
                }
                Lane::Tcp => {
                    let other = sh.queue.iter().any(|j| j.lane == Lane::Http);
                    (sh.active_tcp, sh.tcp_cap, other)
                }
            };
            let active_total = sh.active_http + sh.active_tcp;
            // §3.3 admission: active_total < 6 AND (lane under cap OR other lane's queue empty)
            if active_total < SLOT_CEILING && (lane_active < lane_cap || !other_queued) {
                let job = sh.queue.remove(idx).expect("checked");
                match job.lane {
                    Lane::Http => sh.active_http += 1,
                    Lane::Tcp => sh.active_tcp += 1,
                }
                return Some(job);
            }
            idx += 1;
        }
        None
    }

    fn make_permit(&self, lane: Lane) -> SlotPermit {
        let shared = self.shared.clone();
        let notify = self.notify.clone();
        SlotPermit {
            lane,
            release: Some(Box::new(move || {
                let mut sh = shared.borrow_mut();
                match lane {
                    Lane::Http => sh.active_http -= 1,
                    Lane::Tcp => sh.active_tcp -= 1,
                }
                drop(sh);
                notify.notify();
            })),
        }
    }

    fn release_slot(&self, lane: Lane) {
        let mut sh = self.shared.borrow_mut();
        match lane {
            Lane::Http => sh.active_http -= 1,
            Lane::Tcp => sh.active_tcp -= 1,
        }
        drop(sh);
        self.notify.notify();
    }

    async fn execute(self, job: Job, permit: SlotPermit) {
        match &*job.inner {
            PendingJob::TcpConnect { host, port, replay } => {
                self.exec_tcp_connect(job.sid, host.clone(), *port, replay.clone()).await
            }
            PendingJob::HttpFetch { url, method, headers } => {
                self.exec_http_fetch(job.sid, url.clone(), method.clone(), headers.clone()).await
            }
        }
        drop(permit); // releases the slot and notifies the dispatcher
    }

    async fn exec_tcp_connect(&self, sid: u32, host: String, port: u16, replay: Vec<u8>) {
        let cfg = self.cfg.clone();
        let hub = self.hub_tx.clone();
        let state = self.state.clone();
        {
            let mut st = state.borrow_mut();
            if let Some(s) = st.streams.get_mut(&sid) {
                s.phase = StreamPhase::Active;
            }
        }
        let sock_res = tokio::select! {
            r = async {
                match Socket::builder()
                    .secure_transport(SecureTransport::Off)
                    .connect(&host, port)
                {
                    Ok(s) => s.opened().await.map(|_| s),
                    Err(e) => Err(e),
                }
            } => r,
            _ = worker::Delay::from(std::time::Duration::from_millis(cfg.connect_timeout_ms)) => {
                Err(worker::Error::RustError("connect timeout".into()))
            }
        };
        let mut socket = match sock_res {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                let reason = map_connect_error(&msg, msg.contains("connect timeout"));
                hub.push(HubEvent::Close(sid, reason));
                mark_closed(&state, sid);
                return;
            }
        };
        // socket open: replay any buffered bytes (client DATA sent before/while queued)
        if !replay.is_empty() {
            if let Err(e) = socket.write_all(&replay).await {
                hub.push(HubEvent::Close(sid, map_connect_error(&e.to_string(), false)));
                let _ = socket.close().await;
                mark_closed(&state, sid);
                return;
            }
            update_activity(&state, sid);
        }
        let (mut rd, mut wr) = tokio::io::split(socket);
        let mut chunk = vec![0u8; cfg.data_chunk as usize];
        let opened_ms = now_ms();
        loop {
            // timers
            let (idle_deadline, max_deadline) = {
                let st = state.borrow();
                st.streams
                    .get(&sid)
                    .map(|s| (s.last_activity_ms + cfg.stream_idle_ms, opened_ms + cfg.stream_max_ms))
                    .unwrap_or((0, 0))
            };
            let now = now_ms();
            if now >= idle_deadline || now >= max_deadline {
                hub.push(HubEvent::Close(sid, CR_CUT));
                mark_closed(&state, sid);
                drop(rd);
                return;
            }
            let next_timer = idle_deadline.min(max_deadline);
            let wait_ms = (next_timer - now).min(1000).max(1);
            // pending client DATA (bounded polls of the fifo via short Delay ticks)
            let pending = take_rx(&state, sid);
            if !pending.is_empty() {
                if wr.write_all(&pending).await.is_err() {
                    hub.push(HubEvent::Close(sid, CR_NET_ERROR));
                    mark_closed(&state, sid);
                    return;
                }
                let freed = pending.len();
                hub.push(HubEvent::Continue(sid, (freed / 16384).max(1) as u32));
                update_activity(&state, sid);
            }
            tokio::select! {
                r = rd.read(&mut chunk) => {
                    match r {
                        Ok(0) => { // EOF: upstream closed cleanly
                            hub.push(HubEvent::Close(sid, CR_VOLUNTARY));
                            mark_closed(&state, sid);
                            return;
                        }
                        Ok(n) => {
                            update_activity(&state, sid);
                            let data = Rc::new(chunk[..n].to_vec());
                            if hub.push_await(HubEvent::Data(sid, data), &cfg).await.is_err() {
                                drop(rd);
                                mark_closed(&state, sid);
                                return;
                            }
                        }
                        Err(_) => {
                            hub.push(HubEvent::Close(sid, CR_NET_ERROR));
                            mark_closed(&state, sid);
                            return;
                        }
                    }
                }
                _ = worker::Delay::from(std::time::Duration::from_millis(wait_ms)) => {
                    // loop to re-check timers and drain pending writes
                }
            }
        }
    }

    async fn exec_http_fetch(&self, sid: u32, url: String, method: String, headers: Vec<(String, String)>) {
        let cfg = self.cfg.clone();
        let hub = self.hub_tx.clone();
        let state = self.state.clone();
        {
            let mut st = state.borrow_mut();
            if let Some(s) = st.streams.get_mut(&sid) {
                s.phase = StreamPhase::Active;
            }
        }
        // subrequest budget
        {
            let mut st = state.borrow_mut();
            if st.subrequests >= cfg.subrequest_max {
                hub.synthetic_503(sid);
                hub.push(HubEvent::Close(sid, CR_THROTTLED));
                mark_closed(&state, sid);
                st.rotate_pending = true;
                return;
            }
            st.subrequests += 1;
        }
        let mut req_init = RequestInit::new();
        req_init.method = worker::Method::from(method);
        req_init.redirect = RequestRedirect::Manual;
        let mut h = worker::Headers::new();
        for (k, v) in &headers {
            if HOP_BY_HOP.contains(&k.as_str()) || k == "host" || k == "content-length" {
                continue;
            }
            let _ = h.set(k, v);
        }
        req_init.headers = h;
        let req = match worker::Request::new_with_init(&url, &req_init) {
            Ok(r) => r,
            Err(e) => {
                let reason = map_fetch_error(&e.to_string(), false);
                let body = synthetic_error_response(502, "Bad Gateway", &[]);
                hub.push(HubEvent::Data(sid, Rc::new(body)));
                hub.push(HubEvent::Close(sid, reason));
                mark_closed(&state, sid);
                return;
            }
        };
        let fetch = Fetch::Request(req);
        let fetch_fut = fetch.send();
        let timeout_fut = worker::Delay::from(std::time::Duration::from_millis(cfg.head_timeout_ms));
        let resp = tokio::select! {
            r = fetch_fut => r,
            _ = timeout_fut => {
                const EMPTY: [(&str, &str); 0] = [];
                let body = synthetic_error_response(504, "Gateway Timeout", &EMPTY);
                hub.push(HubEvent::Data(sid, Rc::new(body)));
                hub.push(HubEvent::Close(sid, CR_TIMEOUT));
                mark_closed(&state, sid);
                return;
            }
        };
        let mut resp = match resp {
            Ok(r) => r,
            Err(e) => {
                let reason = map_fetch_error(&e.to_string(), false);
                let body = synthetic_error_response(502, "Bad Gateway", &[]);
                hub.push(HubEvent::Data(sid, Rc::new(body)));
                hub.push(HubEvent::Close(sid, reason));
                mark_closed(&state, sid);
                return;
            }
        };
        // synthetic head + cookies
        let head = build_synthetic_head(resp.status_code(), resp.headers());
        let cookies = build_set_cookie_lines(resp.headers());
        if hub.push_await(HubEvent::Data(sid, Rc::new(head)), &cfg).await.is_err() {
            mark_closed(&state, sid);
            return;
        }
        for c in cookies {
            if hub.push_await(HubEvent::Data(sid, Rc::new(c)), &cfg).await.is_err() {
                mark_closed(&state, sid);
                return;
            }
        }
        // body (decoded: fetch() decodes Content-Encoding transparently)
        let mut stream = match resp.stream() {
            Ok(s) => s,
            Err(_) => {
                hub.push(HubEvent::Close(sid, CR_NET_ERROR));
                mark_closed(&state, sid);
                return;
            }
        };
        let mut sent: u64 = 0;
        use futures::StreamExt as _;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    sent += bytes.len() as u64;
                    if cfg.head_max_bytes != 0 && sent > cfg.head_max_bytes {
                        hub.push(HubEvent::Close(sid, CR_CUT));
                        mark_closed(&state, sid);
                        return;
                    }
                    if cfg.stream_max_bytes != 0 && sent > cfg.stream_max_bytes {
                        hub.push(HubEvent::Close(sid, CR_CUT));
                        mark_closed(&state, sid);
                        return;
                    }
                    if hub
                        .push_await(HubEvent::Data(sid, Rc::new(bytes.to_vec())), &cfg)
                        .await
                        .is_err()
                    {
                        mark_closed(&state, sid);
                        return;
                    }
                }
                Err(_) => {
                    hub.push(HubEvent::Close(sid, CR_NET_ERROR));
                    mark_closed(&state, sid);
                    return;
                }
            }
        }
        hub.push(HubEvent::Close(sid, CR_VOLUNTARY));
        mark_closed(&state, sid);
    }
}

fn take_rx(state: &Shared<SessionState>, sid: u32) -> Vec<u8> {
    let mut st = state.borrow_mut();
    st.streams
        .get_mut(&sid)
        .map(|s| {
            let mut out = Vec::new();
            while let Some(p) = s.rx_fifo.pop_front() {
                out.extend_from_slice(&p);
            }
            out
        })
        .unwrap_or_default()
}

fn update_activity(state: &Shared<SessionState>, sid: u32) {
    if let Some(s) = state.borrow_mut().streams.get_mut(&sid) {
        s.last_activity_ms = now_ms();
    }
}

fn mark_closed(state: &Shared<SessionState>, sid: u32) {
    if let Some(s) = state.borrow_mut().streams.get_mut(&sid) {
        s.phase = StreamPhase::Closed;
    }
}

// --- Egress hub ------------------------------------------------------------

struct HubShared {
    per_stream: HashMap<u32, VecDeque<HubEvent>>,
    order: VecDeque<u32>,
    closed_streams: HashSet<u32>,
    bytes_queued: u64,
    per_stream_bytes: HashMap<u32, u64>,
}

struct HubTx {
    shared: Shared<HubShared>,
    notify: Notify,
    stream_out_cap: u64,
    egress_cap: u64,
    coalesce_max: usize,
    session_done: bool,
}

impl HubTx {
    fn new(cfg: &Config) -> Self {
        HubTx {
            notify: Notify::new(),
            shared: Rc::new(RefCell::new(HubShared {
                per_stream: Default::default(),
                order: Default::default(),
                closed_streams: Default::default(),
                bytes_queued: 0,
                per_stream_bytes: Default::default(),
            })),
            stream_out_cap: cfg.stream_out_cap,
            egress_cap: cfg.egress_cap,
            coalesce_max: cfg.data_chunk as usize,
            session_done: false,
        }
    }

    /// Fire-and-forget push; the hub picks it up.
    fn push(&self, ev: HubEvent) {
        self.queue(ev);
        self.notify.notify();
    }

    fn queue(&self, ev: HubEvent) {
        let sid = match &ev {
            HubEvent::Data(s, _) => *s,
            HubEvent::Close(s, _) => *s,
            HubEvent::Continue(s, _) => *s,
        };
        let mut sh = self.shared.borrow_mut();
        if let HubEvent::Close(s, _) = ev {
            sh.closed_streams.insert(s);
        }
        if let HubEvent::Data(_, d) = &ev {
            if sh.closed_streams.contains(&sid) {
                return; // no DATA after CLOSE
            }
            sh.bytes_queued += d.len() as u64;
            *sh.per_stream_bytes.entry(sid).or_insert(0) += d.len() as u64;
        }
        if !sh.per_stream.contains_key(&sid) {
            sh.order.push_back(sid);
        }
        sh.per_stream.entry(sid).or_default().push_back(ev);
    }

    /// Push with backpressure: producers await when a cap is reached.
    async fn push_await(&self, ev: HubEvent, _cfg: &Config) -> std::result::Result<(), ()> {
        loop {
            {
                let sh = self.shared.borrow();
                let sid = match &ev {
                    HubEvent::Data(s, _) => *s,
                    _ => 0,
                };
                let stream_bytes = sh.per_stream_bytes.get(&sid).copied().unwrap_or(0);
                let over_global = self.egress_cap != 0 && sh.bytes_queued >= self.egress_cap;
                let over_stream = self.stream_out_cap != 0 && stream_bytes >= self.stream_out_cap;
                if !over_global && !over_stream {
                    break;
                }
            }
            // wait for the hub to drain: poll every 5ms (bounded)
            worker::Delay::from(std::time::Duration::from_millis(5)).await;
        }
        self.queue(ev);
        self.notify.notify();
        Ok(())
    }

    fn synthetic_503(&self, sid: u32) {
        let body = synthetic_error_response(503, "Service Unavailable", &[("Retry-After", "1")]);
        self.push(HubEvent::Data(sid, Rc::new(body)));
    }
}

struct HubRunner {
    tx: Rc<HubTx>,
    ws: worker::WebSocket,
    cfg: Rc<Config>,
    rx_notify: Notify,
}

impl HubRunner {
    /// Deficit round-robin (quantum 16 KiB), coalescing, one-CLOSE state machine, pacing.
    async fn run(self, _session_over: Rc<Notify>) {
        let quantum: u64 = 16 * 1024;
        let mut rate_bucket: i128 = 0;
        let mut last_rate_ms = now_ms();
        let HubRunner { tx, ws, cfg, rx_notify } = self;
        let this = HubRunner { tx: tx.clone(), ws, cfg, rx_notify };
        let tx = this.tx.clone();
        loop {
            let n = this.rx_notify.clone(); n.await;
            if this.session_over_flag(&tx) {
                return;
            }
            let mut progress = true;
            while progress {
                progress = false;
                // serve one round: iterate streams in order
                let order_snapshot: Vec<u32> = {
                    let sh = tx.shared.borrow();
                    sh.order.iter().copied().collect()
                };
                for sid in order_snapshot {
                    // serve up to quantum of data
                    let mut coalesced: Vec<u8> = Vec::new();
                    {
                        let mut sh = tx.shared.borrow_mut();
                        while let Some(HubEvent::Data(_, d)) = sh
                            .per_stream
                            .get(&sid)
                            .and_then(|q| q.front().cloned())
                        {
                            if !coalesced.is_empty() && coalesced.len() + d.len() > tx.coalesce_max {
                                break;
                            }
                            if coalesced.len() as u64 >= quantum {
                                break;
                            }
                            let popped = sh
                                .per_stream
                                .get_mut(&sid)
                                .and_then(|q| q.pop_front());
                            if popped.is_none() {
                                break;
                            }
                            sh.bytes_queued = sh.bytes_queued.saturating_sub(d.len() as u64);
                            let e = sh.per_stream_bytes.entry(sid).or_insert(0);
                            *e = e.saturating_sub(d.len() as u64);
                            coalesced.extend_from_slice(&d);
                        }
                    }
                    if !coalesced.is_empty() {
                        // optional token-bucket pacing
                        if this.cfg.egress_rate_bps > 0 {
                            let now = now_ms();
                            let elapsed = (now - last_rate_ms) as i128;
                            last_rate_ms = now;
                            rate_bucket += elapsed * (this.cfg.egress_rate_bps as i128) / 1000;
                            rate_bucket = rate_bucket.min((this.cfg.egress_rate_bps as i128) * 2);
                            let cost = coalesced.len() as i128;
                            if rate_bucket < cost {
                                let deficit_ms =
                                    ((cost - rate_bucket) * 1000 / this.cfg.egress_rate_bps as i128).max(1) as u64;
                                worker::Delay::from(std::time::Duration::from_millis(deficit_ms.min(1000))).await;
                                rate_bucket = 0;
                            } else {
                                rate_bucket -= cost;
                            }
                        }
                        let msg = data_packet(sid, &coalesced);
                        let _ = this.ws.send_with_bytes(&msg);
                        progress = true;
                    }
                    // CONTINUE events for this stream
                    loop {
                        let ev = {
                            let mut sh = tx.shared.borrow_mut();
                            let is_cont = matches!(
                                sh.per_stream.get(&sid).and_then(|q| q.front()),
                                Some(HubEvent::Continue(_, _))
                            );
                            if is_cont {
                                sh.per_stream.get_mut(&sid).and_then(|q| q.pop_front())
                            } else {
                                None
                            }
                        };
                        match ev {
                            Some(HubEvent::Continue(s, v)) => {
                                let _ = this.ws.send_with_bytes(&continue_packet(s, v));
                                progress = true;
                            }
                            _ => break,
                        }
                    }
                    // CLOSE event at the head
                    let close_ev = {
                        let mut sh = tx.shared.borrow_mut();
                        let is_close = matches!(
                            sh.per_stream.get(&sid).and_then(|q| q.front()),
                            Some(HubEvent::Close(_, _))
                        );
                        if is_close {
                            sh.per_stream.get_mut(&sid).and_then(|q| q.pop_front())
                        } else {
                            None
                        }
                    };
                    if let Some(HubEvent::Close(s, r)) = close_ev {
                        let _ = this.ws.send_with_bytes(&close_packet(s, r));
                        {
                            let mut sh = tx.shared.borrow_mut();
                            sh.per_stream.remove(&s);
                            sh.order.retain(|&x| x != s);
                        }
                        progress = true;
                    }
                    // drop empty stream queues
                    {
                        let mut sh = tx.shared.borrow_mut();
                        let empty = sh
                            .per_stream
                            .get(&sid)
                            .map(|q| q.is_empty())
                            .unwrap_or(true);
                        if empty {
                            sh.per_stream.remove(&sid);
                            sh.order.retain(|&x| x != sid);
                        }
                    }
                    if this.session_over_flag(&tx) {
                        return;
                    }
                }
            }
        }
    }

    fn session_over_flag(&self, _tx: &Rc<HubTx>) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// §13 Session — owns the server side of the WebSocketPair
// ---------------------------------------------------------------------------

struct SessionRunner {
    cfg: Rc<Config>,
    state: Shared<SessionState>,
    scheduler: Scheduler,
    hub_tx: Rc<HubTx>,
    ws: worker::WebSocket,
    ws_closed: Rc<Cell<bool>>,
    session_over: Rc<Notify>,
}

impl SessionRunner {
    async fn run_with_server(self, server: worker::WebSocket) {
        let events = server.events().expect("event stream");
        self.run(events).await;
    }

    async fn run(self, events: worker::EventStream<'_>) {
        let SessionRunner { cfg, state, scheduler, hub_tx, ws, ws_closed, session_over } = self;
        let mut events = events;
        console_error!("[wisp] session started: buffer_size={}", cfg.buffer_size);
        // first message: CONTINUE sid 0 with BUFFER_SIZE
        hub_tx.push(HubEvent::Continue(0, cfg.buffer_size));
        // scheduler dispatch loop
        {
            let sch = scheduler.clone_handle();
            wasm_bindgen_futures::spawn_local(sch.run());
        }
        // session timer (drain-and-rotate on SESSION_MAX_MS)
        if cfg.session_max_ms > 0 {
            let ws2 = ws.clone();
            let ws_closed2 = ws_closed.clone();
            let state2 = state.clone();
            let ms = cfg.session_max_ms;
            wasm_bindgen_futures::spawn_local(async move {
                worker::Delay::from(std::time::Duration::from_millis(ms)).await;
                if !ws_closed2.get() {
                    let _ = ws2.close(Some(1001), Some::<&str>("session max"));
                    ws_closed2.set(true);
                    state2.borrow_mut().cancelled = true;
                }
            });
        }
        // main message loop
        use futures::StreamExt as _;
        let ws_handle = ws.clone();
        while let Some(ev) = events.next().await {
            match ev {
                Ok(WebsocketEvent::Message(msg)) => {
                    if let Some(bytes) = msg.bytes() {
                        if bytes.len() < 5 {
                            console_error!("[wisp] ws close 1002: frame too small ({} bytes)", bytes.len());
                            let _ = ws_handle.clone().close(Some(1002), Some::<&str>("frame too small"));
                            ws_closed.set(true);
                            break;
                        }
                        if bytes.len() as u64 > cfg.max_frame_bytes {
                            console_error!("[wisp] ws close 1009: frame {} bytes exceeds {}", bytes.len(), cfg.max_frame_bytes);
                            let _ = ws_handle.clone().close(Some(1009), Some::<&str>("frame too large"));
                            ws_closed.set(true);
                            break;
                        }
                        let p = parse_packet(&bytes).unwrap();
                        dispatch_packet(&cfg, &state, &scheduler, &hub_tx, p.t, p.sid, p.payload);
                    } else if msg.text().is_some() {
                        console_error!("[wisp] ws close 1003: text message received");
                        let _ = ws_handle.clone().close(Some(1003), Some::<&str>("binary frames only"));
                        ws_closed.set(true);
                        break;
                    }
                }
                Ok(WebsocketEvent::Close(_)) | Err(_) => {
                    break;
                }
            }
        }
        // final cleanup: cancel everything and close the server side of the pair
        ws_closed.set(true);
        state.borrow_mut().cancelled = true;
        let st = state.borrow();
        console_error!(
            "[wisp] session ended: streams_opened_total={} streams_remaining={} subrequests={} queue_high_water={}",
            st.total_streams_opened,
            st.streams.len(),
            st.subrequests,
            st.queue_high_water
        );
        drop(st);
        let _ = ws_handle.close(Some(1000), Some::<&str>("session end"));
        session_over.notify();
    }
}

fn dispatch_packet(
    cfg: &Rc<Config>,
    state: &Shared<SessionState>,
    scheduler: &Scheduler,
    hub_tx: &Rc<HubTx>,
    t: u8,
    sid: u32,
    payload: &[u8],
) {
    match t {
        T_CONNECT => {
            if payload.len() < 3 {
                hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                return;
            }
            let stream_type = payload[0];
            let port = u16::from_le_bytes([payload[1], payload[2]]);
            let host = &payload[3..];
            if stream_type != 0x01 {
                // UDP (0x02) or any other type → 0x41
                hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                return;
            }
            if port == 0 {
                hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                return;
            }
            if let Err(reason) = check_target(cfg, host, port) {
                if cfg.http_lane_ports.contains(&port) {
                    let body = synthetic_error_response(403, "Forbidden", &[]);
                    hub_tx.push(HubEvent::Data(sid, Rc::new(body)));
                }
                hub_tx.push(HubEvent::Close(sid, reason));
                return;
            }
            let mut st = state.borrow_mut();
            if st.streams.contains_key(&sid) {
                // duplicate stream ID: tear down the existing stream, then 0x41
                st.streams.remove(&sid);
                drop(st);
                hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                return;
            }
            if st.streams.len() as u32 >= cfg.max_open_streams {
                drop(st);
                if cfg.http_lane_ports.contains(&port) {
                    hub_tx.synthetic_503(sid);
                }
                hub_tx.push(HubEvent::Close(sid, CR_THROTTLED));
                return;
            }
            let host_s = String::from_utf8_lossy(host).trim().to_string();
            let lane = if cfg.http_lane_ports.contains(&port) { Lane::Http } else { Lane::Tcp };
            console_error!(
                "[wisp] stream open: sid={} lane={} {}:{}",
                sid,
                if lane == Lane::Http { "http" } else { "tcp" },
                host_s,
                port
            );
            st.total_streams_opened += 1;
            let now = now_ms();
            st.streams.insert(
                sid,
                StreamCtl {
                    phase: StreamPhase::Pending,
                    lane,
                    host: host_s.clone(),
                    port,
                    rx_fifo: Default::default(),
                    http_buf: Default::default(),
                    bytes_in: 0,
                    bytes_out: 0,
                    opened_ms: now,
                    last_activity_ms: now,
                },
            );
            drop(st);
            if lane == Lane::Tcp {
                {
                    let mut st2 = state.borrow_mut();
                    if let Some(s) = st2.streams.get_mut(&sid) {
                        s.phase = StreamPhase::Queued;
                    }
                }
                let job = Job {
                    sid,
                    lane,
                    inner: Rc::new(PendingJob::TcpConnect { host: host_s, port, replay: Vec::new() }),
                    enqueued_ms: now_ms(),
                };
                if scheduler.enqueue(job).is_err() {
                    hub_tx.push(HubEvent::Close(sid, CR_THROTTLED));
                }
            }
        }
        T_DATA => {
            if payload.is_empty() {
                return;
            }
            let mut st = state.borrow_mut();
            let Some(s) = st.streams.get_mut(&sid) else {
                return; // unknown or already-closed stream: ignore
            };
            if s.phase == StreamPhase::Closed {
                return;
            }
            s.bytes_in += payload.len() as u64;
            s.last_activity_ms = now_ms();
            match s.lane {
                Lane::Tcp => {
                    if s.rx_fifo.len() as u32 + 1 > cfg.buffer_size {
                        s.phase = StreamPhase::Closed;
                        drop(st);
                        hub_tx.push(HubEvent::Close(sid, CR_THROTTLED));
                        return;
                    }
                    s.rx_fifo.push_back(payload.to_vec());
                    drop(st);
                }
                Lane::Http => {
                    if s.phase != StreamPhase::Pending {
                        return; // bytes after the first complete request are discarded
                    }
                    if s.http_buf.len() + payload.len() > cfg.http_head_max as usize {
                        s.phase = StreamPhase::Closed;
                        drop(st);
                        let body = synthetic_error_response(431, "Request Header Fields Too Large", &[]);
                        hub_tx.push(HubEvent::Data(sid, Rc::new(body)));
                        hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                        return;
                    }
                    s.http_buf.extend_from_slice(payload);
                    // strict: bare LF anywhere is fatal (request-smuggling hygiene)
                    if s.http_buf.iter().enumerate().any(|(i, &b)| b == b'\n' && (i == 0 || s.http_buf[i - 1] != b'\r')) {
                        s.phase = StreamPhase::Closed;
                        drop(st);
                        let body = synthetic_error_response(400, "Bad Request", &EMPTY_EXTRAS);
                        hub_tx.push(HubEvent::Data(sid, Rc::new(body)));
                        hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                        return;
                    }
                    let sniffed = looks_like_http_request_line(&s.http_buf);
                    let complete = find_crlfcrlf(&s.http_buf).is_some();
                    let tls = is_tls_record(&s.http_buf);
                    if tls || (!sniffed && complete) {
                        // §3.6 fallback: not an HTTP request → TCP lane or reject
                        match cfg.lane_fallback {
                            LaneFallback::Reject => {
                                s.phase = StreamPhase::Closed;
                                drop(st);
                                hub_tx.push(HubEvent::Close(sid, CR_BLOCKED));
                            }
                            LaneFallback::Tcp => {
                                s.lane = Lane::Tcp;
                                let replay = s.http_buf.clone();
                                s.http_buf.clear();
                                let (host, port) = (s.host.clone(), s.port);
                                s.phase = StreamPhase::Queued;
                                drop(st);
                                let job = Job {
                                    sid,
                                    lane: Lane::Tcp,
                                    inner: Rc::new(PendingJob::TcpConnect { host, port, replay }),
                                    enqueued_ms: now_ms(),
                                };
                                if scheduler.enqueue(job).is_err() {
                                    hub_tx.push(HubEvent::Close(sid, CR_THROTTLED));
                                }
                            }
                        }
                        return;
                    }
                    if complete && sniffed {
                        let buf = s.http_buf.clone();
                        s.phase = StreamPhase::Queued;
                        drop(st);
                        match parse_http_head(&buf, cfg) {
                            Ok(pr) => {
                                let (host, port) = {
                                    let st = state.borrow();
                                    st.streams
                                        .get(&sid)
                                        .map(|x| (x.host.clone(), x.port))
                                        .unwrap()
                                };
                                let scheme = if port == 443 { "https" } else { "http" };
                                let default_port = if port == 443 { 443 } else { 80 };
                                let authority =
                                    if port == default_port { host.clone() } else { format!("{host}:{port}") };
                                let url = format!("{scheme}://{authority}{}", pr.path_and_query);
                                let job = Job {
                                    sid,
                                    lane: Lane::Http,
                                    inner: Rc::new(PendingJob::HttpFetch {
                                        url,
                                        method: pr.method,
                                        headers: pr.headers,
                                    }),
                                    enqueued_ms: now_ms(),
                                };
                                if scheduler.enqueue(job).is_err() {
                                    hub_tx.synthetic_503(sid);
                                    hub_tx.push(HubEvent::Close(sid, CR_THROTTLED));
                                }
                            }
                            Err(reject) => {
                                let body = match reject {
                                    HttpReject::BadRequest => {
                                        synthetic_error_response(400, "Bad Request", &[])
                                    }
                                    HttpReject::HeadTooLarge => synthetic_error_response(
                                        431,
                                        "Request Header Fields Too Large",
                                        &[],
                                    ),
                                    HttpReject::MethodNotAllowed => {
                                        let allow = cfg.http_lane_methods.join(",");
                                        synthetic_error_response(
                                            405,
                                            "Method Not Allowed",
                                            &[("Allow", &allow)],
                                        )
                                    }
                                    HttpReject::UpgradeAttempt => {
                                        synthetic_error_response(501, "Not Implemented", &[])
                                    }
                                };
                                hub_tx.push(HubEvent::Data(sid, Rc::new(body)));
                                hub_tx.push(HubEvent::Close(sid, CR_INVALID));
                            }
                        }
                    }
                }
            }
        }
        T_CONTINUE => {
            // client CONTINUE: ignored (v1 has no server→client credit accounting)
        }
        T_CLOSE => {
            // client CLOSE for a stream: tear it down; the server sends no CLOSE back
            let mut st = state.borrow_mut();
            if st.streams.remove(&sid).is_some() {
                console_error!("[wisp] stream closed by client: sid={}", sid);
            }
        }
        _ => {
            // unknown packet type: ignore
        }
    }
}

// ---------------------------------------------------------------------------
// §14 Router + §15 utilities
// ---------------------------------------------------------------------------

fn json_error(status: u16, msg: &str) -> Result<Response> {
    let body = format!("{{\"error\":\"{msg}\"}}");
    let resp = Response::from_bytes(body.into_bytes())?.with_status(status);
    let mut headers = worker::Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    Ok(resp.with_headers(headers))
}

fn status_response(cfg: &Rc<Config>) -> Result<Response> {
    let body = format!(
        "{{\"version\":\"{}\",\"limits\":{{\"slots\":{},\"head_slots\":{},\"tcp_slots\":{},\"queue_max\":{},\"subrequest_max\":{},\"max_open_streams\":{}}}}}",
        VERSION,
        cfg.head_slots + cfg.tcp_slots,
        cfg.head_slots,
        cfg.tcp_slots,
        cfg.queue_max,
        cfg.subrequest_max,
        cfg.max_open_streams
    );
    let resp = Response::from_bytes(body.into_bytes())?;
    let mut headers = worker::Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    Ok(resp.with_headers(headers))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    let cfg = Rc::new(Config::from_env(&env));
    let url = req.url()?;
    let path = url.path().to_string();

    // WSS only: refuse non-https. Exception: local dev (wrangler dev serves plain http on
    // loopback); production traffic always arrives as https.
    let host_lower = url.host_str().map(|h| h.to_lowercase()).unwrap_or_default();
    let is_loopback_dev = host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1";
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback_dev) {
        return json_error(403, "wss only: non-TLS request refused");
    }
    if req.method() != worker::Method::Get {
        console_error!("[wisp] 405: method {} to {}", req.method(), path);
        return json_error(405, "method not allowed");
    }

    // --- WebSocket upgrade detection FIRST: an upgrade request must never fall into the
    // plain-HTTP branches (that ordering produced the 200-instead-of-101 handshake failure). ---
    let upgrade_header = req
        .headers()
        .get("Upgrade")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_lowercase();
    let wants_ws = upgrade_header.split(',').any(|p| p.trim() == "websocket");

    // Accepted Wisp endpoints: the configured WISP_PATH (default /wisp/) and, for clients that
    // configure the Wisp URL at the root (e.g. Scramjet's epoxy transport), the root path.
    let wisp_path = if cfg.wisp_path.ends_with('/') {
        cfg.wisp_path.clone()
    } else {
        format!("{}/", cfg.wisp_path)
    };
    let is_wisp = match &cfg.wisp_secret {
        Some(secret) => match path.strip_prefix(&wisp_path) {
            Some(rest) => {
                let seg = rest.trim_end_matches('/');
                constant_time_eq(seg, secret)
            }
            None => false,
        },
        None => path == wisp_path || path == "/" || path.is_empty(),
    };

    if wants_ws {
        // ---- WebSocket upgrade path ----
        if !is_wisp {
            console_error!("[wisp] 404: upgrade to non-Wisp path {}", path);
            return json_error(404, "not found");
        }
        if !cfg.allowed_origins.is_empty() {
            let origin = req
                .headers()
                .get("Origin")
                .ok()
                .flatten()
                .map(|o| o.to_lowercase())
                .unwrap_or_default();
            if origin.is_empty() || !cfg.allowed_origins.iter().any(|a| origin == *a) {
                console_error!("[wisp] 403: upgrade rejected, origin not allowed");
                return json_error(403, "origin not allowed");
            }
        }
        console_error!("[wisp] ws upgrade accepted: path={} starting session", path);
        return wisp_session(cfg);
    }

    // ---- plain HTTP branches (only reached when NOT an upgrade) ----
    if path == "/" || path.is_empty() {
        return status_response(&cfg);
    }
    if is_wisp {
        console_error!("[wisp] 426: non-upgrade GET to Wisp path {}", path);
        return json_error(426, "upgrade required");
    }
    console_error!("[wisp] 404: {}", path);
    json_error(404, "not found")
}

/// Accept the WebSocket pair, register the Wisp session handlers, and return the 101
/// with the client side of the pair attached.
fn wisp_session(cfg: Rc<Config>) -> Result<Response> {
    // create the pair and hand the client side back in the 101
    let pair = WebSocketPair::new()?;
    let (client, server) = (pair.client, pair.server);
    server.accept()?;
    console_error!("[wisp] 101: WebSocketPair created, server side accepted");

    let state: Shared<SessionState> = Rc::new(RefCell::new(SessionState {
        streams: Default::default(),
        cancelled: false,
        subrequests: 0,
        queue_high_water: 0,
        rotate_pending: false,
        total_streams_opened: 0,
    }));
    let ws_closed = Rc::new(Cell::new(false));
    let mut hub_tx = HubTx::new(&cfg);
    hub_tx.session_done = false;
    let hub_tx = Rc::new(hub_tx);
    let hub_notify = hub_tx.notify.clone();

    // hub runner: sole writer to the WebSocket
    let session_over = Rc::new(Notify::new());
    {
        let runner = HubRunner {
            tx: hub_tx.clone(),
            ws: server.clone(),
            cfg: cfg.clone(),
            rx_notify: hub_notify,
        };
        let over = session_over.clone();
        wasm_bindgen_futures::spawn_local(runner.run(over));
    }

    let scheduler = Scheduler::new(cfg.clone(), state.clone(), hub_tx.clone(), ws_closed.clone());
    let session = SessionRunner {
        cfg: cfg.clone(),
        state: state.clone(),
        scheduler,
        hub_tx: hub_tx.clone(),
        ws: server.clone(),
        ws_closed: ws_closed.clone(),
        session_over,
    };
    wasm_bindgen_futures::spawn_local(async move {
        // SessionRunner already holds its own WebSocket handle; but `events()` must borrow
        // the same object it listens on. Give the session the moved server itself.
        session.run_with_server(server).await;
    });
    console_error!("[wisp] session live: hub + scheduler + message loop spawned");

    Response::from_websocket(client)
}
