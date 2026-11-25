//! automatic HTTP lane for ports 80/443, and GET head endpoints.
//! Spec: PORT.md (Wisp v1.2 by @ading2210, revised).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use futures::channel::mpsc;
use futures::future::{select, Either};
use futures::stream::StreamExt;
use futures::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use worker::*;

// =====================================================================
// §6.3-1  Config
// =====================================================================

const PROTOCOL_VERSION: &str = "Wisp-CF/1.2 (HTTP profile)";

#[derive(Debug, Clone)]
struct Config {
    path_prefix: String,
    head_slots: usize,
    tcp_slots: usize,
    queue_max: usize,
    queue_wait_ms: u64,
    max_open_streams: usize,
    subrequest_max: u32,
    buffer_size: u32,
    session_max_ms: u64,
    stream_idle_ms: u64,
    connect_timeout_ms: u64,
    batch_idle_ms: u64,
    batch_max_ms: u64,
    batch_max_bytes: u64,
    max_request_bytes: usize,
    stream_out_cap: usize,
    egress_cap: usize,
    http_lane_ports: Vec<u16>,
    http_lane_methods: Vec<String>,
    http_head_max: usize,
    lane_fallback_tcp: bool,
    head_max_bytes: u64,
    head_timeout_ms: u64,
    range_max: u64,
    batch_urls_max: usize,
    max_redirects: u32,
    parallel_ranges: bool,
    split_threshold: u64,
    split_chunk: u64,
    allow_origin: String,
    allow_hosts: Vec<String>,
    block_hosts: Vec<String>,
    auth_token: Option<String>,
    self_host: String,
}

fn env_str(env: &Env, key: &str, default: &str) -> String {
    match env.var(key) {
        Ok(v) => match v.to_string() {
            s if !s.trim().is_empty() => s,
            _ => default.to_string(),
        },
        Err(_) => default.to_string(),
    }
}

fn env_num<T: std::str::FromStr + std::fmt::Display>(env: &Env, key: &str, default: T) -> T {
    let raw = env_str(env, key, &default.to_string());
    match raw.trim().parse::<T>() {
        Ok(v) => v,
        Err(_) => default,
    }
}

fn env_bool(env: &Env, key: &str, default: bool) -> bool {
    let raw = env_str(env, key, if default { "true" } else { "false" });
    matches!(raw.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

impl Config {
    fn from_env(env: &Env) -> Config {
        let mut head_slots = env_num::<usize>(env, "HEAD_SLOTS", 4).max(1);
        let mut tcp_slots = env_num::<usize>(env, "TCP_SLOTS", 2).max(1);
        // Clamp so the sum never exceeds 6: reduce TCP first, then heads,
        // always keeping at least one of each (PORT.md §5).
        while head_slots + tcp_slots > 6 {
            if tcp_slots > 1 {
                tcp_slots -= 1;
            } else if head_slots > 1 {
                head_slots -= 1;
            } else {
                break;
            }
        }
        let http_lane_ports = env_str(env, "HTTP_LANE_PORTS", "80,443")
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect();
        let auth_token = match env.secret("AUTH_TOKEN") {
            Ok(s) => {
                let t = s.to_string();
                if t.is_empty() { None } else { Some(t) }
            }
            Err(_) => None,
        };
        Config {
            path_prefix: env_str(env, "PATH_PREFIX", "").trim().trim_matches('/').to_string(),
            head_slots,
            tcp_slots,
            queue_max: env_num::<usize>(env, "QUEUE_MAX", 64).max(1),
            queue_wait_ms: env_num::<u64>(env, "QUEUE_WAIT_MS", 10_000),
            max_open_streams: env_num::<usize>(env, "MAX_OPEN_STREAMS", 64),
            subrequest_max: env_num::<u32>(env, "SUBREQUEST_MAX", 45),
            buffer_size: env_num::<u32>(env, "BUFFER_SIZE", 128).max(2),
            session_max_ms: env_num::<u64>(env, "SESSION_MAX_MS", 30_000),
            stream_idle_ms: env_num::<u64>(env, "STREAM_IDLE_MS", 15_000),
            connect_timeout_ms: env_num::<u64>(env, "CONNECT_TIMEOUT_MS", 8_000),
            batch_idle_ms: env_num::<u64>(env, "BATCH_IDLE_MS", 350),
            batch_max_ms: env_num::<u64>(env, "BATCH_MAX_MS", 10_000),
            batch_max_bytes: env_num::<u64>(env, "BATCH_MAX_BYTES", 8 * 1024 * 1024),
            max_request_bytes: env_num::<usize>(env, "MAX_REQUEST_BYTES", 4 * 1024 * 1024),
            stream_out_cap: env_num::<usize>(env, "STREAM_OUT_CAP", 1024 * 1024),
            egress_cap: env_num::<usize>(env, "EGRESS_CAP", 8 * 1024 * 1024),
            http_lane_ports,
            http_lane_methods: env_str(env, "HTTP_LANE_METHODS", "GET,HEAD")
                .split(',')
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| !m.is_empty())
                .collect(),
            http_head_max: env_num::<usize>(env, "HTTP_HEAD_MAX", 65_536),
            lane_fallback_tcp: env_str(env, "LANE_FALLBACK", "tcp").trim().eq_ignore_ascii_case("tcp"),
            head_max_bytes: env_num::<u64>(env, "HEAD_MAX_BYTES", 32 * 1024 * 1024),
            head_timeout_ms: env_num::<u64>(env, "HEAD_TIMEOUT_MS", 15_000),
            range_max: env_num::<u64>(env, "RANGE_MAX", 8 * 1024 * 1024),
            batch_urls_max: env_num::<usize>(env, "BATCH_URLS_MAX", 16),
            max_redirects: env_num::<u32>(env, "MAX_REDIRECTS", 5),
            parallel_ranges: env_bool(env, "PARALLEL_RANGES", false),
            split_threshold: env_num::<u64>(env, "SPLIT_THRESHOLD", 4 * 1024 * 1024),
            split_chunk: env_num::<u64>(env, "SPLIT_CHUNK", 2 * 1024 * 1024),
            allow_origin: env_str(env, "ALLOW_ORIGIN", "*"),
            allow_hosts: env_str(env, "ALLOW_HOSTS", "")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            block_hosts: env_str(env, "BLOCK_HOSTS", "")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            auth_token,
            self_host: String::new(),
        }
    }

    fn is_http_lane_port(&self, port: u16) -> bool {
        self.http_lane_ports.contains(&port)
    }
}

// =====================================================================
// §6.3-2  Frame codec
// =====================================================================

const PKT_CONNECT: u8 = 0x01;
const PKT_DATA: u8 = 0x02;
const PKT_CONTINUE: u8 = 0x03;
const PKT_CLOSE: u8 = 0x04;

const MAX_FRAME: u32 = 1_048_576;
const MIN_FRAME: u32 = 5;
pub(crate) const DATA_CHUNK: usize = 16_384;
const COALESCE_MAX: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CloseReason(u8);

impl CloseReason {
    const VOLUNTARY: CloseReason = CloseReason(0x02);
    const NETWORK_ERROR: CloseReason = CloseReason(0x03);
    const INVALID_CONNECT: CloseReason = CloseReason(0x41);
    const UNREACHABLE: CloseReason = CloseReason(0x42);
    const TIMEOUT: CloseReason = CloseReason(0x43);
    const REFUSED: CloseReason = CloseReason(0x44);
    const CUT: CloseReason = CloseReason(0x47);
    const BLOCKED: CloseReason = CloseReason(0x48);
    const THROTTLED: CloseReason = CloseReason(0x49);

    fn code(self) -> u8 { self.0 }
}

/// Encode a Wisp packet as one HTTP frame: [len u32 LE][type][sid u32 LE][payload].
fn encode(pkt_type: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 5 + payload.len());
    out.extend_from_slice(&(5u32 + payload.len() as u32).to_le_bytes());
    out.push(pkt_type);
    out.extend_from_slice(&sid.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn continue_frame(sid: u32, remaining: u32) -> Vec<u8> {
    encode(PKT_CONTINUE, sid, &remaining.to_le_bytes())
}

fn close_frame(sid: u32, reason: CloseReason) -> Vec<u8> {
    encode(PKT_CLOSE, sid, &[reason.code()])
}

/// Split bytes into DATA frames of at most 16384 payload bytes.
fn data_frames(sid: u32, bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    bytes.chunks(DATA_CHUNK).map(|chunk| encode(PKT_DATA, sid, chunk)).collect()
}

/// Incremental frame reader: arbitrary byte chunks in, complete packets out.
/// Rejects frames whose length is < 5 or > 1_048_576; never panics.
#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
    pos: usize,
}

impl FrameReader {
    fn new() -> Self {
        Self::default()
    }

    /// Push a chunk; returns Err(reason) if the framing is corrupt.
    fn push(&mut self, chunk: &[u8]) -> Result<(), &'static str> {
        if chunk.len() + self.buffered() > 16 * 1024 * 1024 {
            return Err("request too large");
        }
        self.buf.extend_from_slice(chunk);
        if self.buffered() >= 4 {
            let len = self.peek_len().unwrap();
            if len < MIN_FRAME {
                return Err("frame length < 5");
            }
            if len > MAX_FRAME {
                return Err("frame length > 1048576");
            }
        }
        Ok(())
    }

    fn peek_len(&self) -> Option<u32> {
        if self.buffered() < 4 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]))
    }

    fn compact(&mut self) {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 256 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    /// Yield the next complete packet (type, sid, payload) if available.
    fn next_packet(&mut self) -> Option<(u8, u32, Vec<u8>)> {
        let len = self.peek_len()? as usize;
        if self.buffered() < 4 + len {
            return None;
        }
        let pkt = &self.buf[self.pos + 4..self.pos + 4 + len];
        let out = (pkt[0], u32::from_le_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]), pkt[5..].to_vec());
        self.pos += 4 + len;
        self.compact();
        Some(out)
    }

    fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }
}

// =====================================================================
// §6.3-3  Destination policy
// =====================================================================

fn is_private_v4(o: [u8; 4]) -> bool {
    let [a, b, ..] = o;
    match a {
        127 => true,                                   // 127/8 loopback
        10 => true,                                    // 10/8 private
        172 => (16..=31).contains(&b),                 // 172.16/12 private
        192 => b == 168,                               // 192.168/16 private
        169 => b == 254,                               // 169.254/16 link-local
        100 => (64..=127).contains(&b),                // 100.64/10 CGNAT
        0 => true,                                     // 0.0.0.0/8 "this host"
        _ => false,
    }
}

fn is_private_v6(groups: &[u16; 8]) -> bool {
    let g = groups;
    if g.iter().all(|&x| x == 0) { return true; }                          // ::
    if g[0..7].iter().all(|&x| x == 0) && g[7] == 1 { return true; }       // ::1
    if (g[0] & 0xfe00) == 0xfc00 { return true; }                          // fc00::/7 ULA
    if (g[0] & 0xffc0) == 0xfe80 { return true; }                          // fe80::/10 link-local
    if let Some(v4) = v4_mapped(g) {
        return is_private_v4(v4);
    }
    false
}

fn v4_mapped(groups: &[u16; 8]) -> Option<[u8; 4]> {
    if groups[0..5].iter().all(|&g| g == 0) && groups[5] == 0xffff {
        Some([(groups[6] >> 8) as u8, groups[6] as u8, (groups[7] >> 8) as u8, groups[7] as u8])
    } else {
        None
    }
}

fn parse_v6_literal(s: &str) -> Option<[u16; 8]> {
    let s = s.strip_prefix('[').map(|x| x.strip_suffix(']').unwrap_or(x)).unwrap_or(s);
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let mut left: Vec<u16> = Vec::new();
    let mut right: Vec<u16> = Vec::new();
    for part in head.split(':') {
        if part.is_empty() { continue; }
        if let Some(v4) = parse_v4_literal(part) {
            left.push((v4[0] as u16) << 8 | v4[1] as u16);
            left.push((v4[2] as u16) << 8 | v4[3] as u16);
            continue;
        }
        left.push(u16::from_str_radix(part, 16).ok()?);
    }
    if let Some(t) = tail {
        for part in t.split(':') {
            if part.is_empty() { continue; }
            if let Some(v4) = parse_v4_literal(part) {
                right.push((v4[0] as u16) << 8 | v4[1] as u16);
                right.push((v4[2] as u16) << 8 | v4[3] as u16);
                continue;
            }
            right.push(u16::from_str_radix(part, 16).ok()?);
        }
    }
    let total = left.len() + right.len();
    match tail {
        Some(_) if total <= 8 => {
            let mut g = [0u16; 8];
            if left.len() > 8 || right.len() > 8 { return None; }
            g[..left.len()].copy_from_slice(&left);
            g[8 - right.len()..].copy_from_slice(&right);
            Some(g)
        }
        Some(_) => None,
        None if total == 8 => {
            let mut g = [0u16; 8];
            g.copy_from_slice(&left);
            Some(g)
        }
        None => None,
    }
}

fn parse_v4_literal(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None; // no leading zeros (strict)
        }
        out[i] = p.parse::<u8>().ok()?;
    }
    Some(out)
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if parse_v4_literal(host).is_some() || parse_v6_literal(host).is_some() {
        return true;
    }
    let h = host.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(host);
    for label in h.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c >= 0x80) {
            return false;
        }
    }
    true
}

/// Cloudflare's published IPv4 ranges (https://www.cloudflare.com/ips-v4),
/// plus the Cloudflare DNS addresses (1.1.1.1, 1.0.0.1) which the runtime
/// also refuses loop connections to. Literal-only checks; the runtime
/// additionally refuses connect() to Cloudflare ranges by hostname.
fn is_cloudflare_v4(o: [u8; 4]) -> bool {
    let [a, b, c, _] = o;
    match (a, b) {
        (1, 1) => c == 1,                          // 1.1.1.1 (Cloudflare DNS)
        (1, 0) => c == 0 && o[3] == 1,             // 1.0.0.1 (Cloudflare DNS)
        (173, 245) => (48..=63).contains(&c),      // 173.245.48.0/20
        (103, 21) => (244..=247).contains(&c),     // 103.21.244.0/22
        (103, 22) => (200..=203).contains(&c),     // 103.22.200.0/22
        (103, 31) => (4..=7).contains(&c),         // 103.31.4.0/22
        (141, 101) => (64..=127).contains(&c),     // 141.101.64.0/18
        (108, 162) => (192..=255).contains(&c),    // 108.162.192.0/18
        (190, 93) => (240..=255).contains(&c),     // 190.93.240.0/20
        (188, 114) => (96..=111).contains(&c),     // 188.114.96.0/20
        (197, 234) => (240..=243).contains(&c),    // 197.234.240.0/22
        (198, 41) => c >= 128,                     // 198.41.128.0/17
        (162, 158) | (162, 159) => true,           // 162.158.0.0/15
        (104, 16..=23) => true,                    // 104.16.0.0/13
        (104, 24..=27) => true,                    // 104.24.0.0/14
        (172, 64..=71) => true,                    // 172.64.0.0/13
        (131, 0) => (72..=75).contains(&c),        // 131.0.72.0/22
        _ => false,
    }
}

struct Policy {
    allow_hosts: Vec<String>,
    block_hosts: Vec<String>,
    self_host: String,
}

impl Policy {
    fn new(cfg: &Config) -> Policy {
        Policy {
            allow_hosts: cfg.allow_hosts.clone(),
            block_hosts: cfg.block_hosts.clone(),
            self_host: cfg.self_host.to_ascii_lowercase(),
        }
    }

    /// Check host:port. Host may be a domain, IPv4 literal or bracketed/plain IPv6.
    fn check_target(&self, host: &str, port: u16) -> Result<(), CloseReason> {
        let host_l = host.trim().to_ascii_lowercase();
        let host_l = host_l
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .map(|x| x.to_string())
            .unwrap_or(host_l);
        if port == 25 {
            return Err(CloseReason::BLOCKED);
        }
        if host_l == "localhost" || host_l.ends_with(".localhost") {
            return Err(CloseReason::BLOCKED);
        }
        if host_l.ends_with(".local") || host_l.ends_with(".internal") {
            return Err(CloseReason::BLOCKED);
        }
        if !host_l.is_empty() && !self.self_host.is_empty() && host_l == self.self_host {
            return Err(CloseReason::BLOCKED);
        }
        if let Some(o) = parse_v4_literal(&host_l) {
            if is_private_v4(o) {
                return Err(CloseReason::BLOCKED);
            }
            if is_cloudflare_v4(o) {
                return Err(CloseReason::BLOCKED);
            }
        } else if let Some(g) = parse_v6_literal(&host_l) {
            if is_private_v6(&g) {
                return Err(CloseReason::BLOCKED);
            }
        }
        for b in &self.block_hosts {
            if host_l == *b || host_l.ends_with(&format!(".{b}")) {
                return Err(CloseReason::BLOCKED);
            }
        }
        if !self.allow_hosts.is_empty() {
            let ok = self
                .allow_hosts
                .iter()
                .any(|a| host_l == *a || host_l.ends_with(&format!(".{a}")));
            if !ok {
                return Err(CloseReason::BLOCKED);
            }
        }
        Ok(())
    }

    /// Validate a head URL (scheme, credentials, then the host policy).
    /// Returns (normalized origin, port, path).
    fn check_url(&self, url: &str) -> Result<(String, u16, String), CloseReason> {
        let (scheme, rest) = url.split_once("://").ok_or(CloseReason::BLOCKED)?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(CloseReason::BLOCKED);
        }
        if rest.contains('@') {
            return Err(CloseReason::BLOCKED); // credentials in URL
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = split_host_port(authority, default_port)?;
        self.check_target(&host, port)?;
        let port_s = if port == default_port { String::new() } else { format!(":{port}") };
        Ok((format!("{scheme}://{host}{port_s}"), port, path.to_string()))
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), CloseReason> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or(CloseReason::INVALID_CONNECT)?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| CloseReason::INVALID_CONNECT)?
        } else {
            default_port
        };
        return Ok((host.to_string(), port));
    }
    match authority.rfind(':') {
        Some(i) => {
            let port = authority[i + 1..]
                .parse::<u16>()
                .map_err(|_| CloseReason::INVALID_CONNECT)?;
            Ok((authority[..i].to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

// =====================================================================
// §6.3-4  HTTP request parser (strict, incremental, bounded)
// =====================================================================

#[derive(Debug)]
struct ParsedRequest {
    method: String,
    path_and_query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
enum ParseOutcome {
    Incomplete,
    NotHttp,
    Complete(ParsedRequest),
    Reject(u16, &'static str),
}

struct RequestParser {
    buf: Vec<u8>,
    started: bool,
    head_done: bool,
    max_head: usize,
    pending_method: Option<String>,
    pending_path: Option<String>,
    pending_headers: Option<Vec<(String, String)>>,
}

impl RequestParser {
    fn new(max_head: usize) -> Self {
        RequestParser {
            buf: Vec::new(),
            started: false,
            head_done: false,
            max_head,
            pending_method: None,
            pending_path: None,
            pending_headers: None,
        }
    }

    fn take_buffered(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    fn feed(&mut self, data: &[u8]) -> ParseOutcome {
        self.buf.extend_from_slice(data);
        if !self.started {
            if self.buf.is_empty() {
                return ParseOutcome::Incomplete;
            }
            // TLS record sniff: 0x16 0x03 0x0[1-4]
            if self.buf.len() >= 3 && self.buf[0] == 0x16 && self.buf[1] == 0x03 && self.buf[2] <= 4 {
                return ParseOutcome::NotHttp;
            }
            if !self.buf[0].is_ascii_uppercase() {
                return ParseOutcome::NotHttp;
            }
            self.started = true;
        }
        if !self.head_done {
            if self.buf.len() > self.max_head {
                return ParseOutcome::Reject(431, "request head too large");
            }
            match find_crlfcrlf(&self.buf) {
                None => ParseOutcome::Incomplete,
                Some(end) => {
                    let head = self.buf[..end].to_vec();
                    let body_rest = self.buf[end + 4..].to_vec();
                    self.buf = body_rest;
                    self.head_done = true;
                    self.parse_head(head)
                }
            }
        } else {
            self.parse_body()
        }
    }

    fn parse_head(&mut self, head: Vec<u8>) -> ParseOutcome {
        let text = match std::str::from_utf8(&head) {
            Ok(t) => t,
            Err(_) => return ParseOutcome::Reject(400, "non-UTF8 request head"),
        };
        // Bare LF / NUL / control characters in the head are rejected.
        for l in text.split("\r\n") {
            if l.contains('\n') {
                return ParseOutcome::Reject(400, "bare LF in request head");
            }
        }
        if text.bytes().any(|b| b == 0 || (b < 0x20 && b != b'\r' && b != b'\n') || b == 0x7f) {
            return ParseOutcome::Reject(400, "control character in request head");
        }
        let mut lines = text.split("\r\n");
        let req_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = req_line.split(' ').collect();
        if parts.len() != 3 {
            return ParseOutcome::Reject(400, "malformed request line");
        }
        let method = parts[0];
        let target = parts[1];
        let version = parts[2];
        if !version.starts_with("HTTP/1.") {
            return ParseOutcome::Reject(400, "unsupported HTTP version");
        }
        if method == "CONNECT" {
            return ParseOutcome::Reject(400, "CONNECT not allowed in lane");
        }
        if !target.starts_with('/') {
            return ParseOutcome::Reject(400, "absolute-form target rejected");
        }
        if target.contains("..") || target.starts_with("//") {
            return ParseOutcome::Reject(400, "suspicious target");
        }
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return ParseOutcome::Reject(400, "obsolete line folding");
            }
            let (name, value) = match line.split_once(':') {
                Some((n, v)) => (n, v.trim_start_matches(' ').trim_end()),
                None => return ParseOutcome::Reject(400, "malformed header line"),
            };
            if name.is_empty() || name.bytes().any(|c| !c.is_ascii_alphanumeric() && c != b'-') {
                return ParseOutcome::Reject(400, "invalid header name");
            }
            if value.bytes().any(|c| c < 0x20 || c == 0x7f) {
                return ParseOutcome::Reject(400, "control character in header value");
            }
            let lower = name.to_ascii_lowercase();
            if (lower == "content-length" || lower == "transfer-encoding")
                && headers.iter().any(|(n, _)| n == &lower)
            {
                return ParseOutcome::Reject(400, "duplicate framing header");
            }
            headers.push((lower, value.to_string()));
        }
        let has_cl = headers.iter().any(|(n, _)| n == "content-length");
        let has_te = headers.iter().any(|(n, _)| n == "transfer-encoding");
        if has_cl && has_te {
            return ParseOutcome::Reject(400, "both Content-Length and Transfer-Encoding");
        }
        if let Some((_, v)) = headers.iter().find(|(n, _)| n == "content-length") {
            if v.is_empty() || (v.len() > 1 && v.starts_with('0')) {
                return ParseOutcome::Reject(400, "bad Content-Length");
            }
            match v.parse::<u64>() {
                Ok(n) if n <= 64 * 1024 * 1024 => {}
                _ => return ParseOutcome::Reject(413, "body too large"),
            }
        }
        if let Some((_, v)) = headers.iter().find(|(n, _)| n == "transfer-encoding") {
            if v.to_ascii_lowercase() != "chunked" {
                return ParseOutcome::Reject(400, "unsupported Transfer-Encoding");
            }
        }
        if let Some((_, v)) = headers.iter().find(|(n, _)| n == "upgrade") {
            if v.to_ascii_lowercase().contains("websocket") {
                return ParseOutcome::Reject(501, "websocket upgrade not supported");
            }
        }
        self.pending_method = Some(method.to_string());
        self.pending_path = Some(target.to_string());
        self.pending_headers = Some(headers);
        self.parse_body()
    }

    fn parse_body(&mut self) -> ParseOutcome {
        let headers = self.pending_headers.as_ref().expect("head parsed");
        let has_te = headers.iter().find(|(n, _)| n == "transfer-encoding");
        let has_cl = headers.iter().find(|(n, _)| n == "content-length");
        if let Some((_, v)) = has_te {
            match decode_chunked(&self.buf) {
                ChunkedResult::Complete((body, consumed)) => {
                    self.buf.drain(..consumed);
                    let req = ParsedRequest {
                        method: self.pending_method.take().unwrap_or_default(),
                        path_and_query: self.pending_path.take().unwrap_or_default(),
                        headers: self.pending_headers.take().unwrap_or_default(),
                        body,
                    };
                    ParseOutcome::Complete(req)
                }
                ChunkedResult::NeedMore => ParseOutcome::Incomplete,
                ChunkedResult::Bad => ParseOutcome::Reject(400, "malformed chunked body"),
            }
        } else if let Some((_, v)) = has_cl {
            let n: usize = v.parse().unwrap_or(0);
            if self.buf.len() < n {
                ParseOutcome::Incomplete
            } else {
                let body = self.buf[..n].to_vec();
                self.buf.drain(..n);
                let req = ParsedRequest {
                    method: self.pending_method.take().unwrap_or_default(),
                    path_and_query: self.pending_path.take().unwrap_or_default(),
                    headers: self.pending_headers.take().unwrap_or_default(),
                    body,
                };
                ParseOutcome::Complete(req)
            }
        } else {
            let req = ParsedRequest {
                method: self.pending_method.take().unwrap_or_default(),
                path_and_query: self.pending_path.take().unwrap_or_default(),
                headers: self.pending_headers.take().unwrap_or_default(),
                body: Vec::new(),
            };
            ParseOutcome::Complete(req)
        }
    }
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

enum ChunkedResult {
    Complete((Vec<u8>, usize)),
    NeedMore,
    Bad,
}

fn decode_chunked(buf: &[u8]) -> ChunkedResult {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let line_end = match find_crlf(buf, pos) {
            Some(i) => i,
            None => return ChunkedResult::NeedMore,
        };
        let size_str = String::from_utf8_lossy(&buf[pos..line_end]).to_string();
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        if size_str.is_empty() || size_str.len() > 8 || !size_str.bytes().all(|c| c.is_ascii_hexdigit()) {
            return ChunkedResult::Bad;
        }
        let size = usize::from_str_radix(&size_str, 16).unwrap_or(usize::MAX);
        pos = line_end + 2;
        if size == 0 {
            // optional trailers until blank line
            match find_crlf(buf, pos) {
                Some(i) => return ChunkedResult::Complete((out, i + 2)),
                None => return ChunkedResult::NeedMore,
            }
        }
        if buf.len() < pos + size + 2 {
            return ChunkedResult::NeedMore;
        }
        out.extend_from_slice(&buf[pos..pos + size]);
        pos += size;
        if &buf[pos..pos + 2] != b"\r\n" {
            return ChunkedResult::Bad;
        }
        pos += 2;
    }
}

fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

// =====================================================================
// §6.3-5  Synthetic response builder
// =====================================================================

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

fn sanitize_header_value(v: &str) -> String {
    let cleaned: Vec<u8> = v
        .bytes()
        .map(|b| if b < 0x20 || b == 0x7f { b' ' } else { b })
        .collect();
    String::from_utf8_lossy(&cleaned).trim().to_string()
}

fn status_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

/// Build the head block of a synthetic HTTP/1.1 response from upstream status
/// and headers: drop hop-by-hop + framing headers (decoded body), add
/// Connection: close, sanitise values, one line per Set-Cookie.
fn synthetic_head(status: u16, headers: &Headers) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", status_reason(status)).into_bytes();
    let mut set_cookies: Vec<String> = Vec::new();
    let mut keys = headers.keys().collect::<Vec<_>>();
    keys.sort();
    for name in keys {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) {
            continue;
        }
        if matches!(lower.as_str(), "content-encoding" | "content-length") {
            continue; // body is decoded; length signalled by CLOSE
        }
        // workerd's Headers.getAll(name) only accepts "Set-Cookie"; every
        // other header must be read with get() (single value, comma-joined).
        if lower == "set-cookie" {
            for v in headers.get_all(&name).unwrap_or_default() {
                set_cookies.push(sanitize_header_value(&v));
            }
            continue;
        }
        if let Ok(Some(v)) = headers.get(&name) {
            let val = sanitize_header_value(&v);
            if !val.is_empty() {
                out.extend_from_slice(format!("{name}: {val}\r\n").as_bytes());
            }
        }
    }
    for c in set_cookies {
        out.extend_from_slice(format!("Set-Cookie: {c}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

fn synthetic_error_head(status: u16, extra: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", status_reason(status)).into_bytes();
    for (n, v) in extra {
        out.extend_from_slice(format!("{n}: {}\r\n", sanitize_header_value(v)).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body.as_bytes());
    out
}

// =====================================================================
// §6.3-6  Error mapping
// =====================================================================

fn map_connect_error(msg: &str, timed_out: bool) -> CloseReason {
    let m = msg.to_ascii_lowercase();
    if timed_out {
        return CloseReason::TIMEOUT;
    }
    // DNS resolution failures first: they are unreachable, not blocked.
    if m.contains("does not resolve")
        || m.contains("resolve")
        || m.contains("dns")
        || m.contains("getaddrinfo")
        || m.contains("enotfound")
        || m.contains("eai_again")
    {
        return CloseReason::UNREACHABLE;
    }
    if m.contains("proxy request failed") || m.contains("tcp loop") || m.contains("prohibited") {
        return CloseReason::BLOCKED;
    }
    if m.contains("refused") {
        return CloseReason::REFUSED;
    }
    if m.contains("timed out") || m.contains("timeout") {
        return CloseReason::TIMEOUT;
    }
    CloseReason::UNREACHABLE
}

fn map_fetch_error(msg: &str, timed_out: bool) -> CloseReason {
    let m = msg.to_ascii_lowercase();
    if timed_out {
        return CloseReason::TIMEOUT;
    }
    if m.contains("refused") {
        return CloseReason::REFUSED;
    }
    if m.contains("timed out") || m.contains("timeout") {
        return CloseReason::TIMEOUT;
    }
    if m.contains("proxy request failed") || m.contains("tcp loop") || m.contains("prohibited") || m.contains("not permitted") {
        return CloseReason::BLOCKED;
    }
    CloseReason::UNREACHABLE
}

// =====================================================================
// §6.3-7  Stream Table
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Pending,
    Queued,
    Active,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Http,
    Tcp,
}

struct StreamEntry {
    state: StreamState,
    lane: Lane,
    host: String,
    port: u16,
    /// Client → upstream FIFO (TCP lane pre-connect, HTTP lane request bytes).
    inbox: VecDeque<Vec<u8>>,
    inbox_packets: usize,
    closed: bool,
    out_bytes: u64,
    in_bytes: u64,
    created_ms: u64,
    parser: Option<RequestParser>,
    writer_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    close_sent: bool,
    idle_deadline_ms: u64,
    virtual_stream: bool,
    replay: Vec<u8>,
}

struct StreamTable {
    map: HashMap<u32, StreamEntry>,
    max_open: usize,
}

impl StreamTable {
    fn new(max_open: usize) -> Self {
        StreamTable { map: HashMap::new(), max_open }
    }

    fn open_count(&self) -> usize {
        self.map.values().filter(|s| s.state != StreamState::Closed).count()
    }

    fn insert(
        &mut self,
        sid: u32,
        host: String,
        port: u16,
        lane: Lane,
        now_ms: u64,
        idle_ms: u64,
        max_head: usize,
        virtual_stream: bool,
    ) -> Result<(), CloseReason> {
        if self.map.contains_key(&sid) {
            return Err(CloseReason::INVALID_CONNECT);
        }
        if self.open_count() >= self.max_open {
            return Err(CloseReason::THROTTLED);
        }
        let parser = if lane == Lane::Http { Some(RequestParser::new(max_head)) } else { None };
        self.map.insert(
            sid,
            StreamEntry {
                state: StreamState::Pending,
                lane,
                host,
                port,
                inbox: VecDeque::new(),
                inbox_packets: 0,
                closed: false,
                out_bytes: 0,
                in_bytes: 0,
                created_ms: now_ms,
                parser,
                writer_tx: None,
                close_sent: false,
                idle_deadline_ms: now_ms + idle_ms,
                virtual_stream,
                replay: Vec::new(),
            },
        );
        Ok(())
    }

    fn get(&self, sid: u32) -> Option<&StreamEntry> {
        self.map.get(&sid)
    }

    fn get_mut(&mut self, sid: u32) -> Option<&mut StreamEntry> {
        self.map.get_mut(&sid)
    }

    fn mark_closed(&mut self, sid: u32) {
        if let Some(s) = self.map.get_mut(&sid) {
            s.state = StreamState::Closed;
            s.closed = true;
            s.writer_tx = None;
            s.parser = None;
            s.inbox.clear();
        }
    }
}

// =====================================================================
// §6.3-8  Job Queue
// =====================================================================

#[derive(Debug)]
enum JobBody {
    TcpConnect,
    HttpLane { method: String, path: String, headers: Vec<(String, String)>, body: Vec<u8> },
    HeadFetch { url: String, kind: HeadKind, redirect: HeadRedirect },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadKind {
    Fetch,
    Meta,
    Range { start: u64, end: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadRedirect {
    Follow,
    Manual,
}

#[derive(Debug)]
struct Job {
    sid: u32,
    lane: Lane,
    enqueued_ms: u64,
    body: JobBody,
}

/// Fair queue: per-stream FIFOs served round-robin.
struct JobQueue {
    per_stream: HashMap<u32, VecDeque<Job>>,
    order: VecDeque<u32>,
    max: usize,
    len: usize,
    high_water: usize,
}

impl JobQueue {
    fn new(max: usize) -> Self {
        JobQueue { per_stream: HashMap::new(), order: VecDeque::new(), max, len: 0, high_water: 0 }
    }

    fn push(&mut self, job: Job) -> Result<(), CloseReason> {
        if self.len >= self.max {
            return Err(CloseReason::THROTTLED);
        }
        let sid = job.sid;
        self.per_stream.entry(sid).or_insert_with(|| {
            self.order.push_back(sid);
            VecDeque::new()
        });
        self.per_stream.get_mut(&sid).unwrap().push_back(job);
        self.len += 1;
        if self.len > self.high_water {
            self.high_water = self.len;
        }
        Ok(())
    }

    /// Next fair job: round-robin across streams, skipping closed streams.
    fn pop(&mut self, closed: &dyn Fn(u32) -> bool) -> Option<Job> {
        while let Some(sid) = self.order.front().copied() {
            let empty_or_closed = self
                .per_stream
                .get(&sid)
                .map(|q| q.is_empty())
                .unwrap_or(true)
                || closed(sid);
            if empty_or_closed {
                let q = self.per_stream.remove(&sid);
                if let Some(q) = q {
                    self.len -= q.len();
                }
                self.order.pop_front();
                continue;
            }
            let job = self.per_stream.get_mut(&sid).unwrap().pop_front().unwrap();
            self.len -= 1;
            self.order.pop_front();
            self.order.push_back(sid);
            return Some(job);
        }
        None
    }

    fn drop_stream(&mut self, sid: u32) {
        if let Some(q) = self.per_stream.remove(&sid) {
            self.len -= q.len();
        }
        self.order.retain(|s| *s != sid);
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn lane_queued(&self, lane: Lane) -> bool {
        self.per_stream.values().any(|q| q.front().map(|j| j.lane == lane).unwrap_or(false))
    }

    /// Push a job back to the front (scheduler could not run it).
    fn push_front(&mut self, job: Job) {
        let sid = job.sid;
        let fresh = !self.per_stream.contains_key(&sid);
        self.per_stream.entry(sid).or_insert_with(VecDeque::new).push_front(job);
        if fresh {
            self.order.push_front(sid);
        }
        self.len += 1;
    }
}

// =====================================================================
// §6.3-9  Scheduler (slot pool, admission, borrowing, subrequest budget)
// =====================================================================

#[derive(Default)]
struct Notify {
    wakers: Vec<std::task::Waker>,
    notified: bool,
}

impl Notify {
    fn register(&mut self, cx: &std::task::Context<'_>) {
        if self.notified {
            self.notified = false;
            cx.waker().wake_by_ref();
            return;
        }
        self.wakers.push(cx.waker().clone());
    }

    fn notify(&mut self) {
        for w in self.wakers.drain(..) {
            w.wake();
        }
        self.notified = true;
    }
}

struct SchedState {
    active_http: usize,
    active_tcp: usize,
    active_total: usize,
    subrequests: u32,
    next_label: usize,
}

struct SchedulerInner {
    state: RefCell<SchedState>,
    wake: RefCell<Notify>,
}

/// Slot permit: released on Drop, wakes the scheduler.
struct SlotPermit {
    inner: Rc<SchedulerInner>,
    http: bool,
    released: bool,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let mut s = self.inner.state.borrow_mut();
        s.active_total = s.active_total.saturating_sub(1);
        if self.http && s.active_http > 0 {
            s.active_http -= 1;
        }
        if !self.http && s.active_tcp > 0 {
            s.active_tcp -= 1;
        }
        drop(s);
        self.inner.wake.borrow_mut().notify();
    }
}

#[derive(Clone)]
struct Scheduler {
    inner: Rc<SchedulerInner>,
    cfg: Rc<Config>,
}

impl Scheduler {
    fn new(cfg: Rc<Config>) -> Scheduler {
        Scheduler {
            inner: Rc::new(SchedulerInner {
                state: RefCell::new(SchedState {
                    active_http: 0,
                    active_tcp: 0,
                    active_total: 0,
                    subrequests: 0,
                    next_label: 0,
                }),
                wake: RefCell::new(Notify::default()),
            }),
            cfg,
        }
    }

    fn executor_label(&self, http: bool) -> String {
        let mut st = self.inner.state.borrow_mut();
        let i = st.next_label;
        st.next_label += 1;
        if http {
            format!("H{}", i % self.cfg.head_slots)
        } else {
            format!("T{}", i % self.cfg.tcp_slots)
        }
    }

    fn take_subrequest(&self) -> bool {
        let mut st = self.inner.state.borrow_mut();
        if st.subrequests >= self.cfg.subrequest_max {
            return false;
        }
        st.subrequests += 1;
        true
    }

    /// Admission rule: active_total < 6 AND (active_L < cap_L OR the other
    /// lane has nothing queued). Borrowing is non-preemptive.
    fn try_acquire(&self, lane: Lane, other_lane_queued: bool) -> Option<SlotPermit> {
        let mut st = self.inner.state.borrow_mut();
        let (active_l, cap_l) = match lane {
            Lane::Http => (st.active_http, self.cfg.head_slots),
            Lane::Tcp => (st.active_tcp, self.cfg.tcp_slots),
        };
        let admit = st.active_total < 6 && (active_l < cap_l || !other_lane_queued);
        if !admit {
            return None;
        }
        st.active_total += 1;
        if lane == Lane::Http {
            st.active_http += 1;
        } else {
            st.active_tcp += 1;
        }
        Some(SlotPermit { inner: self.inner.clone(), http: lane == Lane::Http, released: false })
    }

    /// Future that resolves when a slot is released or a notify happens.
    fn wait_for_wake(&self) -> SlotWait {
        SlotWait { inner: self.inner.clone() }
    }
}

struct SlotWait {
    inner: Rc<SchedulerInner>,
}

impl Future for SlotWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let mut wake = self.inner.wake.borrow_mut();
        wake.register(cx);
        std::task::Poll::Pending
    }
}

// =====================================================================
// §6.3-12  Egress Hub (single writer to the response, DRR fairness)
// =====================================================================

struct HubStreamQ {
    chunks: VecDeque<Vec<u8>>,
    coal: Vec<u8>,
    close: Option<CloseReason>,
    closed_sent: bool,
    deficit: usize,
}

impl HubStreamQ {
    fn queued_bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.len()).sum::<usize>() + self.coal.len()
    }
}

struct EgressHub {
    cfg: Rc<Config>,
    streams: RefCell<HashMap<u32, HubStreamQ>>,
    order: RefCell<VecDeque<u32>>,
    tx: RefCell<Option<mpsc::Sender<Vec<u8>>>>,
    total_bytes: Cell<u64>,
    /// Wakers keyed by sid; sid 0 is the hub drain loop itself.
    waiters: RefCell<HashMap<u32, Vec<std::task::Waker>>>,
    notified: RefCell<bool>,
    done: Cell<bool>,
    /// True once the session signalled it will not register more streams.
    closing: Cell<bool>,
    /// True while the output channel was full at the last drain attempt.
    channel_backpressure: Cell<bool>,
}

const DRR_QUANTUM: usize = 16 * 1024;

impl EgressHub {
    fn new(cfg: Rc<Config>, tx: mpsc::Sender<Vec<u8>>) -> Rc<EgressHub> {
        Rc::new(EgressHub {
            cfg,
            streams: RefCell::new(HashMap::new()),
            order: RefCell::new(VecDeque::new()),
            tx: RefCell::new(Some(tx)),
            total_bytes: Cell::new(0),
            waiters: RefCell::new(HashMap::new()),
            notified: RefCell::new(false),
            done: Cell::new(false),
            closing: Cell::new(false),
            channel_backpressure: Cell::new(false),
        })
    }

    fn ensure_stream(&self, sid: u32) {
        let mut streams = self.streams.borrow_mut();
        if !streams.contains_key(&sid) {
            streams.insert(
                sid,
                HubStreamQ { chunks: VecDeque::new(), coal: Vec::new(), close: None, closed_sent: false, deficit: DRR_QUANTUM },
            );
            self.order.borrow_mut().push_back(sid);
        }
    }

    fn queue_bytes(&self, sid: u32) -> usize {
        self.streams.borrow().get(&sid).map(|s| s.queued_bytes()).unwrap_or(0)
    }

    fn send_data(&self, sid: u32, mut data: Vec<u8>) {
        if data.is_empty() || self.done.get() {
            return;
        }
        self.ensure_stream(sid);
        let mut streams = self.streams.borrow_mut();
        let s = streams.get_mut(&sid).unwrap();
        if s.closed_sent || s.close.is_some() {
            return; // no DATA after CLOSE
        }
        if s.coal.is_empty() && data.len() >= COALESCE_MAX {
            s.chunks.push_back(data);
        } else if s.coal.len() + data.len() <= COALESCE_MAX {
            s.coal.append(&mut data);
            if s.coal.len() >= COALESCE_MAX {
                let chunk = std::mem::take(&mut s.coal);
                s.chunks.push_back(chunk);
            }
        } else {
            let chunk = std::mem::replace(&mut s.coal, data);
            s.chunks.push_back(chunk);
        }
        drop(streams);
        self.wake_hub();
    }

    /// Queue the one and only CLOSE for a stream. Later events are dropped.
    fn send_close(&self, sid: u32, reason: CloseReason) {
        if self.done.get() {
            return;
        }
        self.ensure_stream(sid);
        let mut streams = self.streams.borrow_mut();
        let s = streams.get_mut(&sid).unwrap();
        if s.close.is_some() || s.closed_sent {
            return; // exactly one CLOSE
        }
        s.close = Some(reason);
        drop(streams);
        self.wake_hub();
    }

    fn send_continue(&self, sid: u32, remaining: u32) {
        if self.done.get() {
            return;
        }
        let frame = continue_frame(sid, remaining);
        if let Some(tx) = self.tx.borrow().as_ref() {
            let mut t = tx.clone();
            let _ = t.try_send(frame);
        }
    }

    fn wake_hub(&self) {
        let mut w = self.waiters.borrow_mut();
        if let Some(ws) = w.get_mut(&0) {
            for wk in ws.drain(..) {
                wk.wake();
            }
        }
        *self.notified.borrow_mut() = true;
    }

    fn notify_producers(&self) {
        let mut w = self.waiters.borrow_mut();
        for (_, ws) in w.iter_mut() {
            for wk in ws.drain(..) {
                wk.wake();
            }
        }
    }

    /// Producer-facing backpressure-aware send.
    fn send(self: &Rc<Self>, sid: u32, data: Vec<u8>) -> HubSend {
        HubSend { hub: Rc::clone(self), sid, data: Some(data) }
    }

    /// Drain per-stream queues into the output channel with DRR fairness.
    async fn run(self: &Rc<Self>) {
        loop {
            loop {
                let progressed = self.drain_pass();
                if !progressed {
                    break;
                }
                self.notify_producers();
            }
            if self.all_done() {
                break;
            }
            HubWaitFuture { hub: Rc::clone(self), sid: 0 }.await;
        }
        self.done.set(true);
        *self.tx.borrow_mut() = None; // ends the response body
    }

    /// One DRR pass over the streams. Returns true if any bytes moved.
    fn drain_pass(self: &Rc<Self>) -> bool {
        let mut progressed = false;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        {
            let mut order = self.order.borrow_mut();
            let mut streams = self.streams.borrow_mut();
            let mut finished: Vec<u32> = Vec::new();
            let mut i = 0;
            while i < order.len() {
                let sid = order[i];
                let Some(s) = streams.get_mut(&sid) else {
                    finished.push(sid);
                    i += 1;
                    continue;
                };
                // flush the coalescing buffer when the queue would go idle
                if s.chunks.is_empty() && !s.coal.is_empty() {
                    let chunk = std::mem::take(&mut s.coal);
                    s.chunks.push_back(chunk);
                }
                let mut served = 0usize;
                while let Some(front) = s.chunks.front() {
                    if served + front.len() > s.deficit && served > 0 {
                        break;
                    }
                    let chunk = s.chunks.pop_front().unwrap();
                    served += chunk.len();
                    self.total_bytes.set(self.total_bytes.get() + chunk.len() as u64);
                    for f in data_frames(sid, &chunk) {
                        frames.push(f);
                    }
                    if served >= s.deficit {
                        break;
                    }
                }
                s.deficit = s.deficit.saturating_sub(served) + DRR_QUANTUM;
                if served > 0 {
                    progressed = true;
                }
                // CLOSE only after all data flushed
                if s.chunks.is_empty() && s.coal.is_empty() {
                    if let Some(reason) = s.close.take() {
                        if !s.closed_sent {
                            s.closed_sent = true;
                            frames.push(close_frame(sid, reason));
                        }
                    }
                    if s.closed_sent {
                        finished.push(sid);
                    }
                }
                i += 1;
            }
            for sid in finished {
                order.retain(|s| *s != sid);
                streams.remove(&sid);
            }
        }
        // Send frames outside the RefCell borrows. If the channel is full,
        // stop draining (the response stream will pull more soon).
        if !frames.is_empty() {
            if let Some(tx) = self.tx.borrow().as_ref() {
                let mut t = tx.clone();
                let mut i = 0;
                while i < frames.len() {
                    match t.try_send(frames[i].clone()) {
                        Ok(()) => i += 1,
                        Err(_) => break,
                    }
                }
                if i < frames.len() {
                    self.channel_backpressure.set(true);
                    // frames not sent: nothing lost — drain_pass already
                    // popped them from per-stream queues, so re-queue them.
                    self.restore_unsent(frames, i);
                    // partial progress only
                } else {
                    self.channel_backpressure.set(false);
                }
            }
        }
        progressed
    }

    /// Push unsent frames (already encoded) back to the front of their
    /// streams so nothing is dropped when the output channel is full.
    fn restore_unsent(&self, frames: Vec<Vec<u8>>, from: usize) {
        let mut streams = self.streams.borrow_mut();
        for f in frames.into_iter().skip(from) {
            if f.len() < 9 {
                continue;
            }
            let t = f[4];
            let sid = u32::from_le_bytes([f[5], f[6], f[7], f[8]]);
            let payload = f[9..].to_vec();
            let s = streams.entry(sid).or_insert_with(|| {
                self.order.borrow_mut().push_back(sid);
                HubStreamQ { chunks: VecDeque::new(), coal: Vec::new(), close: None, closed_sent: false, deficit: DRR_QUANTUM }
            });
            if t == PKT_DATA {
                s.chunks.push_front(payload);
            } else if t == PKT_CLOSE {
                s.close = Some(CloseReason(payload[0]));
                s.closed_sent = false;
            }
        }
    }

    fn all_done(&self) -> bool {
        if !self.closing.get() {
            return false; // session still running: never end the response early
        }
        let streams = self.streams.borrow();
        streams.iter().all(|(_, s)| s.closed_sent)
            && streams.iter().all(|(sid, _)| self.order.borrow().contains(sid))
    }

    fn open_count(&self) -> usize {
        self.streams.borrow().iter().filter(|(_, s)| !s.closed_sent).count()
    }

    /// Shutdown: CLOSE(reason) every non-closed stream, flush, end.
    fn shutdown(&self, reason: CloseReason) {
        self.closing.set(true);
        let mut streams = self.streams.borrow_mut();
        let sids: Vec<u32> = streams
            .iter()
            .filter(|(_, s)| !s.closed_sent && s.close.is_none())
            .map(|(sid, _)| *sid)
            .collect();
        for sid in sids {
            if let Some(s) = streams.get_mut(&sid) {
                s.close = Some(reason);
            }
        }
        drop(streams);
        self.wake_hub();
    }
}

/// Backpressure-aware producer send future.
struct HubSend {
    hub: Rc<EgressHub>,
    sid: u32,
    data: Option<Vec<u8>>,
}

impl Future for HubSend {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let global_ok = (self.hub.total_bytes.get() as usize) < self.hub.cfg.egress_cap;
        let stream_ok = self.hub.queue_bytes(self.sid) < self.hub.cfg.stream_out_cap;
        if global_ok && stream_ok {
            let data = self.data.take().expect("data only taken on Ready");
            self.hub.send_data(self.sid, data);
            return std::task::Poll::Ready(());
        }
        let mut w = self.hub.waiters.borrow_mut();
        w.entry(self.sid).or_default().push(cx.waker().clone());
        std::task::Poll::Pending
    }
}

struct HubWaitFuture {
    hub: Rc<EgressHub>,
    sid: u32,
}

impl Future for HubWaitFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.sid == 0 && *self.hub.notified.borrow() {
            *self.hub.notified.borrow_mut() = false;
            return std::task::Poll::Ready(());
        }
        if self.sid != 0 {
            let global_ok = (self.hub.total_bytes.get() as usize) < self.hub.cfg.egress_cap;
            let stream_ok = self.hub.queue_bytes(self.sid) < self.hub.cfg.stream_out_cap;
            if global_ok && stream_ok {
                return std::task::Poll::Ready(());
            }
        }
        let mut w = self.hub.waiters.borrow_mut();
        w.entry(self.sid).or_default().push(cx.waker().clone());
        std::task::Poll::Pending
    }
}

// =====================================================================
// Shared session context
// =====================================================================

struct SessionCtx {
    cfg: Rc<Config>,
    hub: Rc<EgressHub>,
    sched: Scheduler,
    policy: Policy,
    streams: RefCell<StreamTable>,
    queue: RefCell<JobQueue>,
    deadline_ms: u64,
    cancelled: Cell<bool>,
    subrequest_denied: Cell<u32>,
    queue_full_events: Cell<u32>,
    active_labels: RefCell<Vec<String>>,
}

impl SessionCtx {
    fn closed_stream(&self, sid: u32) -> bool {
        let st = self.streams.borrow();
        st.get(sid).map(|s| s.closed || s.state == StreamState::Closed).unwrap_or(true)
    }

    fn fail_queue_full(&self, sid: u32) {
        let lane = self.streams.borrow().get(sid).map(|s| s.lane).unwrap_or(Lane::Tcp);
        if lane == Lane::Http {
            self.hub.send_data(
                sid,
                synthetic_error_head(503, &[("Retry-After", "1")], "queue full, retry later\n"),
            );
        }
        self.hub.send_close(sid, CloseReason::THROTTLED);
        self.queue.borrow_mut().drop_stream(sid);
        self.streams.borrow_mut().mark_closed(sid);
    }

    fn log(&self, line: String) {
        console_log!("{line}");
    }
}

// =====================================================================
// §6.3-10  Head executor (HTTP lane + /head/* endpoints)
// =====================================================================

fn status_for_reason(reason: CloseReason) -> u16 {
    match reason {
        CloseReason::REFUSED => 502,
        CloseReason::TIMEOUT => 504,
        CloseReason::BLOCKED => 403,
        CloseReason::THROTTLED => 503,
        _ => 502,
    }
}

async fn run_http_job(ctx: Rc<SessionCtx>, job: Job, permit: SlotPermit, label: String) {
    let sid = job.sid;
    let start = Date::now().as_millis();
    let wait_ms = start - job.enqueued_ms;

    let lane_name = if matches!(job.body, JobBody::TcpConnect) { "tcp" } else { "http" };
    match job.body {
        JobBody::HttpLane { method, path, headers, body } => {
            http_lane_fetch(&ctx, sid, method, path, headers, body).await
        }
        JobBody::HeadFetch { url, kind, redirect } => head_fetch(&ctx, sid, url, kind, redirect).await,
        JobBody::TcpConnect => Ok(()),
    }
    .ok();
    let now = Date::now().as_millis();
    ctx.log(format!(
        "{{\"sid\":{sid},\"lane\":\"{lane_name}\",\"executor\":\"{label}\",\"wait_ms\":{wait_ms},\"run_ms\":{}}}",
        now - start
    ));
    drop(permit);
}

/// HTTP-lane fetch: target fixed by CONNECT, hop-by-hop stripped, redirect=manual.
async fn http_lane_fetch(
    ctx: &Rc<SessionCtx>,
    sid: u32,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<(), CloseReason> {
    let (host, port) = {
        let st = ctx.streams.borrow();
        let s = st.get(sid).ok_or(CloseReason::INVALID_CONNECT)?;
        (s.host.clone(), s.port)
    };
    ctx.policy.check_target(&host, port)?;
    if !ctx.sched.take_subrequest() {
        ctx.hub.send_data(sid, synthetic_error_head(503, &[], "subrequest budget exhausted\n"));
        ctx.hub.send_close(sid, CloseReason::THROTTLED);
        ctx.streams.borrow_mut().mark_closed(sid);
        return Ok(());
    }
    let scheme = if port == 443 { "https" } else { "http" };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let port_s = if port != default_port { format!(":{port}") } else { String::new() };
    let url = format!("{scheme}://{host}{port_s}{path}");

    let mut fwd = Headers::new();
    for (name, value) in &headers {
        if HOP_BY_HOP.contains(&name.as_str()) || name == "host" || name == "content-length" {
            continue;
        }
        let _ = fwd.append(name, value);
    }

    let method_up = if method == "HEAD" { Method::Head } else { Method::Get };
    let mut init = RequestInit::new();
    init.with_method(method_up)
        .with_headers(fwd)
        .with_redirect(RequestRedirect::Manual); // 3xx goes to the client unchanged
    if !body.is_empty() {
        let js = js_sys::Uint8Array::from(&body[..]);
        init.with_body(Some(js.into()));
    }

    let req = match Request::new_with_init(&url, &init) {
        Ok(r) => r,
        Err(e) => {
            let reason = map_fetch_error(&e.to_string(), false);
            ctx.hub.send_data(sid, synthetic_error_head(status_for_reason(reason), &[], "bad gateway\n"));
            ctx.hub.send_close(sid, reason);
            ctx.streams.borrow_mut().mark_closed(sid);
            return Ok(());
        }
    };

    let fetch = Fetch::Request(req);
    let fetch_fut = fetch.send();
    let timeout = Delay::from(std::time::Duration::from_millis(ctx.cfg.head_timeout_ms));
    let mut resp = match select(Box::pin(fetch_fut), Box::pin(timeout)).await {
        Either::Left((Ok(r), _)) => r,
        Either::Left((Err(e), _)) => {
            let reason = map_fetch_error(&e.to_string(), false);
            ctx.hub.send_data(sid, synthetic_error_head(status_for_reason(reason), &[], "upstream failure\n"));
            ctx.hub.send_close(sid, reason);
            ctx.streams.borrow_mut().mark_closed(sid);
            return Ok(());
        }
        Either::Right(_) => {
            ctx.hub.send_data(sid, synthetic_error_head(504, &[], "upstream timeout\n"));
            ctx.hub.send_close(sid, CloseReason::TIMEOUT);
            ctx.streams.borrow_mut().mark_closed(sid);
            return Ok(());
        }
    };

    let status = resp.status_code();
    let head_block = synthetic_head(status, resp.headers());
    ctx.hub.clone().send(sid, head_block).await;

    let mut total: u64 = 0;
    let mut body_stream: Box<dyn Stream<Item = Result<Vec<u8>>> + Unpin> = match resp.stream() {
        Ok(s) => Box::new(s),
        Err(_) => Box::new(futures::stream::empty()),
    };
    let close_reason = loop {
        let chunk_fut = body_stream.next();
        let timeout = Delay::from(std::time::Duration::from_millis(ctx.cfg.head_timeout_ms));
        match select(Box::pin(chunk_fut), Box::pin(timeout)).await {
            Either::Left((Some(Ok(chunk)), _)) => {
                total += chunk.len() as u64;
                if total > ctx.cfg.head_max_bytes {
                    break CloseReason::CUT;
                }
                if ctx.closed_stream(sid) {
                    break CloseReason::VOLUNTARY;
                }
                ctx.hub.clone().send(sid, chunk).await;
            }
            Either::Left((Some(Err(_)), _)) => break CloseReason::NETWORK_ERROR,
            Either::Left((None, _)) => break CloseReason::VOLUNTARY,
            Either::Right(_) => break CloseReason::TIMEOUT,
        }
    };
    ctx.hub.send_close(sid, close_reason);
    ctx.streams.borrow_mut().mark_closed(sid);
    Ok(())
}

/// /head/* fetch: manual redirect loop, policy re-checked on every hop.
async fn head_fetch(
    ctx: &Rc<SessionCtx>,
    sid: u32,
    url: String,
    kind: HeadKind,
    redirect_mode: HeadRedirect,
) -> Result<(), CloseReason> {
    if let Err(reason) = ctx.policy.check_url(&url) {
        ctx.hub.send_data(sid, synthetic_error_head(403, &[], "destination blocked\n"));
        ctx.hub.send_close(sid, reason);
        ctx.streams.borrow_mut().mark_closed(sid);
        return Ok(());
    }
    let mut current = url;

    let mut hops: u32 = 0;
    let mut resp = loop {
        if !ctx.sched.take_subrequest() {
            ctx.hub.send_data(sid, synthetic_error_head(503, &[], "subrequest budget exhausted\n"));
            ctx.hub.send_close(sid, CloseReason::THROTTLED);
            ctx.streams.borrow_mut().mark_closed(sid);
            return Ok(());
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_redirect(RequestRedirect::Manual);
        let req = match Request::new_with_init(&current, &init) {
            Ok(r) => r,
            Err(e) => {
                let reason = map_fetch_error(&e.to_string(), false);
                ctx.hub.send_data(sid, synthetic_error_head(status_for_reason(reason), &[], "bad gateway\n"));
                ctx.hub.send_close(sid, reason);
                ctx.streams.borrow_mut().mark_closed(sid);
                return Ok(());
            }
        };
        let fetch = Fetch::Request(req);
        let fetch_fut = fetch.send();
        let timeout = Delay::from(std::time::Duration::from_millis(ctx.cfg.head_timeout_ms));
        let mut resp = match select(Box::pin(fetch_fut), Box::pin(timeout)).await {
            Either::Left((Ok(r), _)) => r,
            Either::Left((Err(e), _)) => {
                let reason = map_fetch_error(&e.to_string(), false);
                ctx.hub.send_data(sid, synthetic_error_head(status_for_reason(reason), &[], "upstream failure\n"));
                ctx.hub.send_close(sid, reason);
                ctx.streams.borrow_mut().mark_closed(sid);
                return Ok(());
            }
            Either::Right(_) => {
                ctx.hub.send_data(sid, synthetic_error_head(504, &[], "upstream timeout\n"));
                ctx.hub.send_close(sid, CloseReason::TIMEOUT);
                ctx.streams.borrow_mut().mark_closed(sid);
                return Ok(());
            }
        };
        let status = resp.status_code();
        if (300..400).contains(&status) {
            let loc = resp.headers().get("Location").ok().flatten();
            if let Some(loc) = loc {
                if redirect_mode == HeadRedirect::Manual {
                    let head_block = synthetic_head(status, resp.headers());
                    ctx.hub.clone().send(sid, head_block).await;
                    ctx.hub.send_close(sid, CloseReason::VOLUNTARY);
                    ctx.streams.borrow_mut().mark_closed(sid);
                    return Ok(());
                }
                hops += 1;
                if hops > ctx.cfg.max_redirects {
                    ctx.hub.send_data(sid, synthetic_error_head(503, &[], "too many redirects\n"));
                    ctx.hub.send_close(sid, CloseReason::THROTTLED);
                    ctx.streams.borrow_mut().mark_closed(sid);
                    return Ok(());
                }
                let next = resolve_url(&current, &loc);
                match ctx.policy.check_url(&next) {
                    Ok(_) => current = next,
                    Err(reason) => {
                        // redirect hop denied: synthetic 403 + CLOSE 0x48
                        ctx.hub.send_data(sid, synthetic_error_head(403, &[], "redirect hop blocked\n"));
                        ctx.hub.send_close(sid, reason);
                        ctx.streams.borrow_mut().mark_closed(sid);
                        return Ok(());
                    }
                }
                continue;
            }
        }
        break resp;
    };

    let status = resp.status_code();

    // /head/range with a 200 upstream: skip and truncate server-side.
    if let HeadKind::Range { start: rstart, end: rend } = kind {
        if status == 200 {
            let head_block = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {rstart}-{rend}/*\r\nConnection: close\r\n\r\n"
            )
            .into_bytes();
            ctx.hub.clone().send(sid, head_block).await;
            let want = rend - rstart + 1;
            let mut skipped: u64 = 0;
            let mut delivered: u64 = 0;
            let mut body_stream: Box<dyn Stream<Item = Result<Vec<u8>>> + Unpin> = match resp.stream() {
                Ok(s) => Box::new(s),
                Err(_) => Box::new(futures::stream::empty()),
            };
            let close_reason = loop {
                let chunk_fut = body_stream.next();
                let timeout = Delay::from(std::time::Duration::from_millis(ctx.cfg.head_timeout_ms));
                match select(Box::pin(chunk_fut), Box::pin(timeout)).await {
                    Either::Left((Some(Ok(mut chunk)), _)) => {
                        if skipped < rstart {
                            let skip = ((rstart - skipped) as usize).min(chunk.len());
                            skipped += skip as u64;
                            chunk.drain(..skip);
                        }
                        if !chunk.is_empty() {
                            let take = ((want - delivered) as usize).min(chunk.len());
                            delivered += take as u64;
                            let out = chunk[..take].to_vec();
                            ctx.hub.clone().send(sid, out).await;
                            if delivered >= want {
                                break CloseReason::VOLUNTARY;
                            }
                        }
                    }
                    Either::Left((Some(Err(_)), _)) => break CloseReason::NETWORK_ERROR,
                    Either::Left((None, _)) => break CloseReason::VOLUNTARY,
                    Either::Right(_) => break CloseReason::TIMEOUT,
                }
            };
            ctx.hub.send_close(sid, close_reason);
            ctx.streams.borrow_mut().mark_closed(sid);
            return Ok(());
        }
        // 206: pass through (head block includes Content-Range)
    }

    let head_block = synthetic_head(status, resp.headers());
    ctx.hub.clone().send(sid, head_block).await;

    if kind == HeadKind::Meta {
        ctx.hub.send_close(sid, CloseReason::VOLUNTARY);
        ctx.streams.borrow_mut().mark_closed(sid);
        return Ok(());
    }

    let mut total: u64 = 0;
    let mut body_stream: Box<dyn Stream<Item = Result<Vec<u8>>> + Unpin> = match resp.stream() {
        Ok(s) => Box::new(s),
        Err(_) => Box::new(futures::stream::empty()),
    };
    let close_reason = loop {
        let chunk_fut = body_stream.next();
        let timeout = Delay::from(std::time::Duration::from_millis(ctx.cfg.head_timeout_ms));
        match select(Box::pin(chunk_fut), Box::pin(timeout)).await {
            Either::Left((Some(Ok(chunk)), _)) => {
                total += chunk.len() as u64;
                if total > ctx.cfg.head_max_bytes {
                    break CloseReason::CUT;
                }
                if ctx.closed_stream(sid) {
                    break CloseReason::VOLUNTARY;
                }
                ctx.hub.clone().send(sid, chunk).await;
            }
            Either::Left((Some(Err(_)), _)) => break CloseReason::NETWORK_ERROR,
            Either::Left((None, _)) => break CloseReason::VOLUNTARY,
            Either::Right(_) => break CloseReason::TIMEOUT,
        }
    };
    ctx.hub.send_close(sid, close_reason);
    ctx.streams.borrow_mut().mark_closed(sid);
    Ok(())
}

/// Resolve a Location header against the current URL (absolute or relative).
fn resolve_url(current: &str, location: &str) -> String {
    let loc = location.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let (scheme, rest) = current.split_once("://").unwrap_or(("https", current));
    let origin_end = rest.find('/').unwrap_or(rest.len());
    let origin = &rest[..origin_end];
    if loc.starts_with('/') {
        return format!("{scheme}://{origin}{loc}");
    }
    let base_path = &rest[origin_end..];
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..i + 1],
        None => "/",
    };
    format!("{scheme}://{origin}{dir}{loc}")
}

// =====================================================================
// §6.3-11  TCP executor
// =====================================================================

async fn run_tcp_job(ctx: Rc<SessionCtx>, job: Job, permit: SlotPermit, label: String) {
    let sid = job.sid;
    let start = Date::now().as_millis();
    let wait_ms = start - job.enqueued_ms;
    let (host, port) = {
        let st = ctx.streams.borrow();
        match st.get(sid) {
            Some(s) => (s.host.clone(), s.port),
            None => return,
        }
    };

    if let Err(reason) = ctx.policy.check_target(&host, port) {
        ctx.hub.send_close(sid, reason);
        ctx.streams.borrow_mut().mark_closed(sid);
        let now = Date::now().as_millis();
        ctx.log(format!(
            "{{\"sid\":{sid},\"lane\":\"tcp\",\"executor\":\"{label}\",\"wait_ms\":{wait_ms},\"run_ms\":{},\"close\":\"0x{:02x}\"}}",
            now - start,
            reason.code()
        ));
        return;
    }

    let socket = match Socket::builder().secure_transport(SecureTransport::Off).connect(&host, port) {
        Ok(s) => s,
        Err(e) => {
            let reason = map_connect_error(&e.to_string(), false);
            ctx.hub.send_close(sid, reason);
            ctx.streams.borrow_mut().mark_closed(sid);
            let now = Date::now().as_millis();
            ctx.log(format!(
                "{{\"sid\":{sid},\"lane\":\"tcp\",\"executor\":\"{label}\",\"wait_ms\":{wait_ms},\"run_ms\":{},\"close\":\"0x{:02x}\"}}",
                now - start,
                reason.code()
            ));
            return;
        }
    };

    let opened_ok = {
        let opened_fut = socket.opened();
        let timeout = Delay::from(std::time::Duration::from_millis(ctx.cfg.connect_timeout_ms));
        match select(Box::pin(opened_fut), Box::pin(timeout)).await {
            Either::Left((Ok(_), _)) => Ok(()),
            Either::Left((Err(e), _)) => Err(map_connect_error(&e.to_string(), false)),
            Either::Right(_) => Err(CloseReason::TIMEOUT),
        }
    };
    if let Err(reason) = opened_ok {
        ctx.hub.send_close(sid, reason);
        let mut sock = socket;
        let _ = sock.close().await;
        ctx.streams.borrow_mut().mark_closed(sid);
        let now = Date::now().as_millis();
        ctx.log(format!(
            "{{\"sid\":{sid},\"lane\":\"tcp\",\"executor\":\"{label}\",\"wait_ms\":{wait_ms},\"run_ms\":{},\"close\":\"0x{:02x}\"}}",
            now - start,
            reason.code()
        ));
        return;
    }

    // Active: hand the writer channel to the session and replay buffered bytes.
    let (wtx, mut wrx) = mpsc::unbounded::<Vec<u8>>();
    {
        let mut st = ctx.streams.borrow_mut();
        if let Some(s) = st.get_mut(sid) {
            s.writer_tx = Some(wtx.clone());
            s.state = StreamState::Active;
            for b in s.inbox.drain(..) {
                let _ = wtx.unbounded_send(b);
            }
            if !s.replay.is_empty() {
                let r = std::mem::take(&mut s.replay);
                let _ = wtx.unbounded_send(r);
            }
            s.inbox_packets = 0;
        } else {
            return;
        }
    }

    let (mut reader, mut writer) = tokio::io::split(socket);
    let hub = ctx.hub.clone();
    let cfg = ctx.cfg.clone();
    let bytes_in = Rc::new(Cell::new(0u64));
    let bytes_out = Rc::new(Cell::new(0u64));

    // Reader task: socket → hub (16 KiB reads with backpressure), idle deadline.
    let reader_fut = async {
        let mut buf = vec![0u8; DATA_CHUNK];
        loop {
            let read_fut = reader.read(&mut buf);
            let idle = Delay::from(std::time::Duration::from_millis(cfg.stream_idle_ms));
            match select(Box::pin(read_fut), Box::pin(idle)).await {
                Either::Left((Ok(0), _)) => break CloseReason::VOLUNTARY,
                Either::Left((Ok(n), _)) => {
                    bytes_in.set(bytes_in.get() + n as u64);
                    let chunk = buf[..n].to_vec();
                    hub.clone().send(sid, chunk).await;
                }
                Either::Left((Err(e), _)) => {
                    break map_connect_error(&e.to_string(), false);
                }
                Either::Right(_) => break CloseReason::CUT,
            }
        }
    };

    // Writer task: FIFO → socket, CONTINUE accounting.
    let writer_fut = async {
        let mut sent_since_continue: usize = 0;
        while let Some(chunk) = wrx.next().await {
            if ctx.closed_stream(sid) {
                break;
            }
            bytes_out.set(bytes_out.get() + chunk.len() as u64);
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
            sent_since_continue += 1;
            if sent_since_continue >= (cfg.buffer_size as usize) / 2 {
                sent_since_continue = 0;
                let queued = {
                    let st = ctx.streams.borrow();
                    st.get(sid).map(|s| s.inbox_packets).unwrap_or(0)
                };
                hub.send_continue(sid, cfg.buffer_size.saturating_sub(queued as u32));
            }
        }
        let _ = writer.flush().await;
    };

    // Run reader and writer concurrently; the reader's exit sets the close
    // reason. Lease/cancel are checked on a short tick.
    let mut reader_pin = Box::pin(reader_fut);
    let mut writer_pin = Box::pin(writer_fut);
    let close_reason;
    loop {
        if Date::now().as_millis() > ctx.deadline_ms || ctx.cancelled.get() {
            close_reason = CloseReason::CUT;
            break;
        }
        let poll_tick = Delay::from(std::time::Duration::from_millis(20));
        // Race: reader completion vs writer completion vs tick.
        match select(select(&mut reader_pin, &mut writer_pin), Box::pin(poll_tick)).await {
            Either::Left((Either::Left((reason, writer_again)), _)) => {
                // Reader finished: writer still needed for a grace flush.
                let _ = writer_again;
                close_reason = reason;
                break;
            }
            Either::Left((Either::Right((_w, reader_again)), _)) => {
                // Writer finished (client closed its sending side): keep
                // reading until EOF/idle; loop continues with the reader.
                let _ = reader_again;
                // Poll the reader alone against ticks now.
                loop {
                    if Date::now().as_millis() > ctx.deadline_ms || ctx.cancelled.get() {
                        close_reason = CloseReason::CUT;
                        writer_pin.as_mut().await;
                        ctx.hub.send_close(sid, close_reason);
                        ctx.streams.borrow_mut().mark_closed(sid);
                        let now = Date::now().as_millis();
                        ctx.log(format!(
                            "{{\"sid\":{sid},\"lane\":\"tcp\",\"executor\":\"{label}\",\"wait_ms\":{wait_ms},\"run_ms\":{},\"bytes_in\":{},\"bytes_out\":{},\"close\":\"0x{:02x}\"}}",
                            now - start, bytes_in.get(), bytes_out.get(), close_reason.code()
                        ));
                        drop(permit);
                        return;
                    }
                    let tick2 = Delay::from(std::time::Duration::from_millis(20));
                    match select(&mut reader_pin, Box::pin(tick2)).await {
                        Either::Left((reason, _)) => {
                            close_reason = reason;
                            break;
                        }
                        Either::Right(_) => {}
                    }
                    if ctx.closed_stream(sid) {
                        close_reason = CloseReason::VOLUNTARY;
                        break;
                    }
                }
                break;
            }
            Either::Right(_) => {}
        }
        if ctx.closed_stream(sid) {
            close_reason = CloseReason::VOLUNTARY;
            break;
        }
    }
    drop(wtx); // stop the writer
    // Give the writer a short grace to flush, then proceed regardless —
    // the reader's exit reason is authoritative.
    {
        let grace = Delay::from(std::time::Duration::from_millis(50));
        match select(writer_pin, Box::pin(grace)).await {
            Either::Left(_) => {}
            Either::Right(_) => {}
        }
    }
    ctx.hub.send_close(sid, close_reason);
    ctx.streams.borrow_mut().mark_closed(sid);
    let now = Date::now().as_millis();
    ctx.log(format!(
        "{{\"sid\":{sid},\"lane\":\"tcp\",\"executor\":\"{label}\",\"wait_ms\":{wait_ms},\"run_ms\":{},\"bytes_in\":{},\"bytes_out\":{},\"close\":\"0x{:02x}\"}}",
        now - start,
        bytes_in.get(),
        bytes_out.get(),
        close_reason.code()
    ));
    drop(permit);
}

// =====================================================================
// §6.3-13  Session
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionMode {
    Duplex,
    Batch,
}

struct Session {
    ctx: Rc<SessionCtx>,
}

impl Session {
    fn new(cfg: Rc<Config>, hub: Rc<EgressHub>, sched: Scheduler) -> Session {
        let policy = Policy::new(&cfg);
        let now = Date::now().as_millis();
        let ctx = Rc::new(SessionCtx {
            cfg: cfg.clone(),
            hub: hub.clone(),
            sched: sched.clone(),
            policy,
            streams: RefCell::new(StreamTable::new(cfg.max_open_streams)),
            queue: RefCell::new(JobQueue::new(cfg.queue_max)),
            deadline_ms: now + cfg.session_max_ms,
            cancelled: Cell::new(false),
            subrequest_denied: Cell::new(0),
            queue_full_events: Cell::new(0),
            active_labels: RefCell::new(Vec::new()),
        });
        Session { ctx }
    }

    /// Scheduler loop: fair dispatch, queue deadlines, lease enforcement.
    /// `input_done` gates the batch exit conditions: until the request body
    /// has been fully read, the loop must keep running even if momentarily
    /// idle (the next frame may still arrive).
    async fn scheduler_loop(self: Rc<Self>, input_done: Rc<Cell<bool>>) {
        let ctx = self.ctx.clone();
        let mut batch_start: Option<u64> = None;
        loop {
            let now = Date::now().as_millis();
            if ctx.cancelled.get() || now > ctx.deadline_ms {
                break;
            }

            // Expire stale queued jobs (QUEUE_WAIT_MS).
            let expired: Vec<u32> = {
                let q = ctx.queue.borrow();
                let mut expired = Vec::new();
                for (sid, v) in q.per_stream.iter() {
                    if v.front().map(|j| now - j.enqueued_ms > ctx.cfg.queue_wait_ms).unwrap_or(false) {
                        expired.push(*sid);
                    }
                }
                expired
            };
            for sid in expired {
                ctx.queue_full_events.set(ctx.queue_full_events.get() + 1);
                ctx.fail_queue_full(sid);
            }

            // Fair dispatch with admission + borrowing.
            let mut maybe: Option<(Job, SlotPermit)> = None;
            {
                let closed = |sid: u32| ctx.closed_stream(sid);
                let mut q = ctx.queue.borrow_mut();
                if let Some(job) = q.pop(&closed) {
                    let http_queued = q.lane_queued(Lane::Http);
                    let tcp_queued = q.lane_queued(Lane::Tcp);
                    let other_queued = if job.lane == Lane::Http { tcp_queued } else { http_queued };
                    if let Some(permit) = ctx.sched.try_acquire(job.lane, other_queued) {
                        maybe = Some((job, permit));
                    } else {
                        q.push_front(job);
                    }
                }
            }
            match maybe {
                Some((job, permit)) => {
                    let label = ctx.sched.executor_label(job.lane == Lane::Http);
                    ctx.active_labels.borrow_mut().push(label.clone());
                    let ctx2 = ctx.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        match job.lane {
                            Lane::Http => run_http_job(ctx2.clone(), job, permit, label.clone()).await,
                            Lane::Tcp => run_tcp_job(ctx2.clone(), job, permit, label.clone()).await,
                        }
                        ctx2.active_labels.borrow_mut().retain(|l| *l != label);
                    });
                }
                None => {
                    // nothing runnable now: wait for a slot release or new job
                    let wait = ctx.sched.wait_for_wake();
                    let _ = select(Box::pin(wait), Box::pin(Delay::from(std::time::Duration::from_millis(25)))).await;
                }
            }

            // Batch-mode exit conditions (only after the whole request body
            // has been read — before that, more frames may still arrive).
            let streams_open = ctx.streams.borrow().open_count();
            if input_done.get() && ctx.queue.borrow().is_empty() && streams_open == 0 {
                if batch_start.is_none() {
                    batch_start = Some(Date::now().as_millis());
                } else if Date::now().as_millis() - batch_start.unwrap() > ctx.cfg.batch_idle_ms {
                    break;
                }
            } else {
                batch_start = None;
            }
            if ctx.hub.total_bytes.get() >= ctx.cfg.batch_max_bytes {
                break;
            }
            if Date::now().as_millis() > ctx.deadline_ms {
                break;
            }
        }
        // graceful shutdown of everything still open
        self.shutdown(CloseReason::CUT).await;
    }

    async fn shutdown(&self, reason: CloseReason) {
        let ctx = &self.ctx;
        ctx.cancelled.set(true);
        let open: Vec<u32> = {
            let st = ctx.streams.borrow();
            st.map
                .iter()
                .filter(|(_, s)| !s.close_sent && !s.closed)
                .map(|(sid, _)| *sid)
                .collect()
        };
        for sid in open {
            ctx.hub.send_close(sid, reason);
            ctx.streams.borrow_mut().mark_closed(sid);
        }
        ctx.hub.shutdown(reason);
    }

    /// POST /wisp/ driver.
    async fn run_wisp(self: Rc<Self>, mode: SessionMode, mut body: ByteStream, input_done: Rc<Cell<bool>>) {
        let ctx = self.ctx.clone();
        let cfg = ctx.cfg.clone();

        // The first frame of every response: stream-0 CONTINUE.
        ctx.hub.send_continue(0, cfg.buffer_size);

        let mut reader = FrameReader::new();
        let mut eof = false;
        let mut batch_deadline: Option<u64> = None;

        loop {
            if Date::now().as_millis() > ctx.deadline_ms || ctx.cancelled.get() {
                self.shutdown(CloseReason::CUT).await;
                return;
            }

            if !eof {
                match body.next().await {
                    Some(Ok(chunk)) => {
                        if reader.buffered() + chunk.len() > cfg.max_request_bytes {
                            self.shutdown(CloseReason::CUT).await;
                            return;
                        }
                        if let Err(reason) = reader.push(&chunk) {
                            console_error!("frame error: {reason}");
                            self.shutdown(CloseReason::CUT).await;
                            return;
                        }
                    }
                    Some(Err(_)) => {
                        self.shutdown(CloseReason::CUT).await;
                        return;
                    }
                    None => {
                        eof = true;
                        input_done.set(true);
                        if mode == SessionMode::Duplex {
                            // client ended its request body: close out politely
                            let open: Vec<u32> = {
                                let st = ctx.streams.borrow();
                                st.map
                                    .iter()
                                    .filter(|(_, s)| !s.close_sent && !s.closed)
                                    .map(|(sid, _)| *sid)
                                    .collect()
                            };
                            for sid in open {
                                ctx.hub.send_close(sid, CloseReason::VOLUNTARY);
                                ctx.streams.borrow_mut().mark_closed(sid);
                            }
                            ctx.hub.shutdown(CloseReason::VOLUNTARY);
                            return;
                        }
                        batch_deadline = Some(Date::now().as_millis() + cfg.batch_max_ms);
                    }
                }
            }

            // process complete packets
            while let Some((t, sid, payload)) = reader.next_packet() {
                if ctx.cancelled.get() {
                    return;
                }
                match t {
                    PKT_CONNECT => self.handle_connect(sid, &payload),
                    PKT_DATA => self.handle_data(sid, payload),
                    PKT_CLOSE => {
                        ctx.queue.borrow_mut().drop_stream(sid);
                        ctx.streams.borrow_mut().mark_closed(sid);
                    }
                    _ => {} // client CONTINUE and unknown types: ignored
                }
            }

            if mode == SessionMode::Batch && eof {
                let now = Date::now().as_millis();
                let settled = ctx.queue.borrow().is_empty() && ctx.streams.borrow().open_count() == 0;
                if settled {
                    self.shutdown(CloseReason::VOLUNTARY).await;
                    return;
                }
                if let Some(d) = batch_deadline {
                    if now > d {
                        self.shutdown(CloseReason::CUT).await;
                        return;
                    }
                }
                if ctx.hub.total_bytes.get() >= cfg.batch_max_bytes {
                    self.shutdown(CloseReason::CUT).await;
                    return;
                }
                Delay::from(std::time::Duration::from_millis(20)).await;
                continue;
            }
        }
    }

    fn handle_connect(&self, sid: u32, payload: &[u8]) {
        let ctx = &self.ctx;
        let cfg = &ctx.cfg;
        if sid == 0 || payload.len() < 3 {
            ctx.hub.send_close(sid, CloseReason::INVALID_CONNECT);
            return;
        }
        let stream_type = payload[0];
        let port = u16::from_le_bytes([payload[1], payload[2]]);
        let host = String::from_utf8_lossy(&payload[3..]).to_string();
        if stream_type != 0x01 {
            // 0x02 UDP (and anything else) → 0x41
            ctx.hub.send_close(sid, CloseReason::INVALID_CONNECT);
            return;
        }
        if port == 0 || !is_valid_hostname(&host) {
            ctx.hub.send_close(sid, CloseReason::INVALID_CONNECT);
            return;
        }
        if port == 25 {
            ctx.hub.send_close(sid, CloseReason::BLOCKED);
            return;
        }
        // duplicate sid → 0x41 and tear the existing stream down
        if ctx.streams.borrow().map.contains_key(&sid) {
            ctx.queue.borrow_mut().drop_stream(sid);
            ctx.streams.borrow_mut().mark_closed(sid);
            ctx.hub.send_close(sid, CloseReason::INVALID_CONNECT);
            return;
        }
        // policy on the destination
        if let Err(reason) = ctx.policy.check_target(&host, port) {
            ctx.hub.send_close(sid, reason);
            return;
        }
        let now = Date::now().as_millis();
        let lane = if cfg.is_http_lane_port(port) { Lane::Http } else { Lane::Tcp };
        let mut st = ctx.streams.borrow_mut();
        if let Err(reason) = st.insert(sid, host.clone(), port, lane, now, cfg.stream_idle_ms, cfg.http_head_max, false) {
            drop(st);
            ctx.hub.send_close(sid, reason);
            return;
        }
        drop(st);
        if lane == Lane::Tcp {
            let job = Job { sid, lane, enqueued_ms: now, body: JobBody::TcpConnect };
            if ctx.queue.borrow_mut().push(job).is_err() {
                ctx.fail_queue_full(sid);
            }
        }
        // HTTP lane: wait for request bytes
    }

    fn handle_data(&self, sid: u32, data: Vec<u8>) {
        let ctx = &self.ctx;
        let cfg = &ctx.cfg;
        let lane_and_tx = {
            let st = ctx.streams.borrow();
            st.get(sid)
                .filter(|s| !s.closed)
                .map(|s| (s.lane, s.writer_tx.clone()))
        };
        let Some((lane, writer_tx)) = lane_and_tx else { return };
        match lane {
            Lane::Http => self.http_lane_feed(sid, data),
            Lane::Tcp => {
                if let Some(tx) = writer_tx {
                    let _ = tx.unbounded_send(data);
                } else {
                    let mut st = ctx.streams.borrow_mut();
                    let Some(s) = st.get_mut(sid) else { return };
                    s.inbox_packets += 1;
                    s.in_bytes += data.len() as u64;
                    if s.inbox.len() >= cfg.buffer_size as usize {
                        drop(st);
                        ctx.queue.borrow_mut().drop_stream(sid);
                        ctx.hub.send_close(sid, CloseReason::THROTTLED);
                        ctx.streams.borrow_mut().mark_closed(sid);
                        return;
                    }
                    s.inbox.push_back(data);
                }
            }
        }
    }

    fn http_lane_feed(&self, sid: u32, data: Vec<u8>) {
        let ctx = &self.ctx;
        let cfg = &ctx.cfg;
        let outcome = {
            let mut st = ctx.streams.borrow_mut();
            let Some(s) = st.get_mut(sid) else { return };
            let Some(parser) = s.parser.as_mut() else { return };
            parser.feed(&data)
        };
        match outcome {
            ParseOutcome::Incomplete => {}
            ParseOutcome::NotHttp => {
                let do_fallback = cfg.lane_fallback_tcp;
                {
                    let mut st = ctx.streams.borrow_mut();
                    let Some(s) = st.get_mut(sid) else { return };
                    let mut parser = s.parser.take().unwrap();
                    let buffered = parser.take_buffered();
                    if do_fallback {
                        s.lane = Lane::Tcp;
                        s.replay = buffered;
                        s.state = StreamState::Pending;
                    }
                }
                if do_fallback {
                    let now = Date::now().as_millis();
                    let job = Job { sid, lane: Lane::Tcp, enqueued_ms: now, body: JobBody::TcpConnect };
                    if ctx.queue.borrow_mut().push(job).is_err() {
                        ctx.fail_queue_full(sid);
                    }
                } else {
                    ctx.hub.send_close(sid, CloseReason::BLOCKED);
                    ctx.streams.borrow_mut().mark_closed(sid);
                }
            }
            ParseOutcome::Reject(status, why) => {
                ctx.hub.send_data(sid, synthetic_error_head(status, &[], &format!("{why}\n")));
                ctx.hub.send_close(sid, CloseReason::INVALID_CONNECT);
                ctx.streams.borrow_mut().mark_closed(sid);
            }
            ParseOutcome::Complete(req) => {
                if !cfg.http_lane_methods.iter().any(|m| m == &req.method) {
                    let allow = cfg.http_lane_methods.join(", ");
                    ctx.hub.send_data(sid, synthetic_error_head(405, &[("Allow", &allow)], "method not allowed\n"));
                    ctx.hub.send_close(sid, CloseReason::INVALID_CONNECT);
                    ctx.streams.borrow_mut().mark_closed(sid);
                    return;
                }
                let now = Date::now().as_millis();
                {
                    let mut st = ctx.streams.borrow_mut();
                    if let Some(s) = st.get_mut(sid) {
                        s.state = StreamState::Queued;
                        s.parser = None;
                    }
                }
                let job = Job {
                    sid,
                    lane: Lane::Http,
                    enqueued_ms: now,
                    body: JobBody::HttpLane {
                        method: req.method,
                        path: req.path_and_query,
                        headers: req.headers,
                        body: req.body,
                    },
                };
                if ctx.queue.borrow_mut().push(job).is_err() {
                    ctx.fail_queue_full(sid);
                }
            }
        }
    }
}

// =====================================================================
// §6.3-14 + 15  Router and utilities
// =====================================================================

fn cors_headers(cfg: &Config, preflight: bool) -> Vec<(String, String)> {
    let mut h = Vec::new();
    h.push(("Access-Control-Allow-Origin".to_string(), cfg.allow_origin.clone()));
    if preflight {
        h.push(("Access-Control-Allow-Methods".to_string(), "GET, POST, OPTIONS".to_string()));
        h.push((
            "Access-Control-Allow-Headers".to_string(),
            "content-type, authorization, x-wisp-mode, x-wisp-fwd-accept, x-wisp-fwd-accept-language, x-wisp-fwd-user-agent, x-wisp-fwd-referer, x-wisp-fwd-cookie, x-wisp-fwd-if-none-match, x-wisp-fwd-if-modified-since".to_string(),
        ));
        h.push(("Access-Control-Max-Age".to_string(), "86400".to_string()));
    } else {
        h.push(("Access-Control-Expose-Headers".to_string(), "content-type".to_string()));
    }
    h
}

fn apply_headers(resp: &mut Response, headers: &[(String, String)]) {
    let h = resp.headers_mut();
    for (n, v) in headers {
        let _ = h.set(n, v);
    }
}

fn json_error(status: u16, msg: &str) -> Result<Response> {
    let body = serde_json::json!({ "error": msg });
    let mut resp = Response::from_json(&body)?;
    resp = resp.with_status(status);
    Ok(resp)
}

thread_local! {
    static COUNTERS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

fn countup(counter: &str) {
    COUNTERS.with(|c| {
        *c.borrow_mut().entry(counter.to_string()).or_insert(0) += 1;
    });
}

fn counters_snapshot() -> String {
    COUNTERS.with(|c| {
        let c = c.borrow();
        let mut v: Vec<(String, u64)> = c.iter().map(|(k, x)| (k.clone(), *x)).collect();
        v.sort();
        v.iter().map(|(k, x)| format!("\"{k}\":{x}")).collect::<Vec<_>>().join(",")
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => out.push((percent_decode(k), percent_decode(v))),
            None => out.push((percent_decode(pair), String::new())),
        }
    }
    out
}

fn wisp_response(cfg: &Config, out_rx: mpsc::Receiver<Vec<u8>>) -> Result<Response> {
    let out_stream = out_rx.map(|chunk| Ok::<Vec<u8>, Error>(chunk));
    let mut resp = Response::from_stream(out_stream)?;
    {
        let h = resp.headers_mut();
        let _ = h.set("Content-Type", "application/x-wisp-frames");
        let _ = h.set("Cache-Control", "no-store, no-transform");
        let _ = h.set("X-Content-Type-Options", "nosniff");
    }
    apply_headers(&mut resp, &cors_headers(cfg, false));
    Ok(resp)
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    let cfg = Rc::new(Config::from_env(&env));

    let url = req.url()?;
    let path = url.path().to_string();
    let prefix = if cfg.path_prefix.is_empty() {
        String::new()
    } else {
        format!("/{}", cfg.path_prefix)
    };
    let stripped = if !prefix.is_empty() && path.starts_with(&prefix) {
        path[prefix.len()..].to_string()
    } else {
        path
    };

    // OPTIONS preflight
    if req.method() == Method::Options {
        let mut resp = Response::empty()?;
        resp = resp.with_status(204);
        apply_headers(&mut resp, &cors_headers(&cfg, true));
        return Ok(resp);
    }

    // Origin check (only when ALLOW_ORIGIN is not *)
    if cfg.allow_origin != "*" {
        if let Some(origin) = req.headers().get("Origin").ok().flatten() {
            if origin != cfg.allow_origin {
                return json_error(403, "origin not allowed");
            }
        }
    }

    // Auth
    if let Some(token) = &cfg.auth_token {
        let provided = req
            .headers()
            .get("Authorization")
            .ok()
            .flatten()
            .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string()));
        match provided {
            Some(p) if constant_time_eq(p.as_bytes(), token.as_bytes()) => {}
            _ => return json_error(401, "missing or invalid token"),
        }
    }

    // GET / — config + counters
    if stripped == "/" && req.method() == Method::Get {
        countup("root");
        let body = format!(
            "{{\"version\":\"{PROTOCOL_VERSION}\",\"limits\":{{\"max_concurrent_upstream\":6,\"heads\":{},\"tcp_slots\":{},\"queue_max\":{},\"subrequest_max\":{},\"session_max_ms\":{},\"buffer_size\":{}}},\"counters\":{{{}}}}}",
            cfg.head_slots,
            cfg.tcp_slots,
            cfg.queue_max,
            cfg.subrequest_max,
            cfg.session_max_ms,
            cfg.buffer_size,
            counters_snapshot()
        );
        let mut resp = Response::from_bytes(body.into_bytes())?;
        {
            let h = resp.headers_mut();
            let _ = h.set("Content-Type", "application/json");
        }
        apply_headers(&mut resp, &cors_headers(&cfg, false));
        return Ok(resp);
    }

    let method = req.method();
    let is_post_wisp = stripped == "/wisp/" || stripped == "/wisp";
    let head_kind = stripped.strip_prefix("/head/").map(|s| s.to_string());

    if is_post_wisp {
        if method != Method::Post {
            return json_error(405, "POST required");
        }
        let ct = req.headers().get("Content-Type").ok().flatten().unwrap_or_default();
        if !ct.starts_with("application/x-wisp-frames") {
            return json_error(415, "content-type must be application/x-wisp-frames");
        }
        let mode_hdr = req.headers().get("X-Wisp-Mode").ok().flatten().unwrap_or_default();
        let mode = if mode_hdr.eq_ignore_ascii_case("duplex") { SessionMode::Duplex } else { SessionMode::Batch };
        countup("wisp_sessions");

        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
        let hub = EgressHub::new(cfg.clone(), out_tx);
        let sched = Scheduler::new(cfg.clone());
        let session = Rc::new(Session::new(cfg.clone(), hub.clone(), sched));

        let mut body_stream = req.stream()?;
        let input_done = Rc::new(Cell::new(false));
        let sched_fut = {
            let s = session.clone();
            let input_done = input_done.clone();
            async move { s.scheduler_loop(input_done).await }
        };
        let wisp_fut = {
            let s = session.clone();
            let input_done = input_done.clone();
            async move { s.run_wisp(mode, body_stream, input_done).await }
        };
        let hub_fut = async move { hub.run().await };
        ctx.wait_until(sched_fut);
        ctx.wait_until(wisp_fut);
        ctx.wait_until(hub_fut);
        return wisp_response(&cfg, out_rx);
    }

    if let Some(kind) = head_kind {
        if method != Method::Get {
            return json_error(405, "GET required");
        }
        countup("head_requests");
        let query = url.query().unwrap_or("");
        let params = parse_query(query);
        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let get_all = |k: &str| params.iter().filter(|(n, _)| n == k).map(|(_, v)| v.clone()).collect::<Vec<_>>();

        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
        let hub = EgressHub::new(cfg.clone(), out_tx);
        let sched = Scheduler::new(cfg.clone());
        let session = Rc::new(Session::new(cfg.clone(), hub.clone(), sched));

        let base_sid: u32 = get("sid").and_then(|s| s.parse().ok()).unwrap_or(1);

        let mut specs: Vec<(u32, JobBody)> = Vec::new();
        match kind.as_str() {
            "fetch" | "meta" => {
                let Some(furl) = get("url") else {
                    return json_error(400, "missing url parameter");
                };
                let redirect = match get("redirect").as_deref() {
                    Some("manual") => HeadRedirect::Manual,
                    _ => HeadRedirect::Follow,
                };
                let hk = if kind == "fetch" { HeadKind::Fetch } else { HeadKind::Meta };
                specs.push((base_sid, JobBody::HeadFetch { url: furl, kind: hk, redirect }));
            }
            "range" => {
                let Some(rurl) = get("url") else {
                    return json_error(400, "missing url parameter");
                };
                let start: u64 = get("start").and_then(|s| s.parse().ok()).unwrap_or(0);
                let Some(end_s) = get("end") else {
                    return json_error(400, "missing start/end parameters");
                };
                let Ok(end) = end_s.parse::<u64>() else {
                    return json_error(400, "invalid end parameter");
                };
                if end < start || end - start + 1 > cfg.range_max {
                    return json_error(400, "invalid range");
                }
                specs.push((base_sid, JobBody::HeadFetch { url: rurl, kind: HeadKind::Range { start, end }, redirect: HeadRedirect::Follow }));
            }
            "batch" => {
                let urls = get_all("u");
                if urls.is_empty() {
                    return json_error(400, "missing u parameters");
                }
                if urls.len() > cfg.batch_urls_max {
                    return json_error(400, "too many urls");
                }
                for (i, u) in urls.iter().enumerate() {
                    specs.push((base_sid + i as u32, JobBody::HeadFetch { url: u.clone(), kind: HeadKind::Fetch, redirect: HeadRedirect::Follow }));
                }
            }
            _ => return json_error(404, "unknown head endpoint"),
        }

        // Register virtual streams + queue jobs (they run via the same
        // scheduler and egress hub as /wisp/).
        let now = Date::now().as_millis();
        {
            let mut st = session.ctx.streams.borrow_mut();
            for (sid, _) in &specs {
                let _ = st.insert(*sid, String::new(), 443, Lane::Http, now, cfg.stream_idle_ms, cfg.http_head_max, true);
            }
        }
        session.ctx.hub.send_continue(0, cfg.buffer_size);
        for (sid, body) in specs {
            let job = Job { sid, lane: Lane::Http, enqueued_ms: now, body };
            if session.ctx.queue.borrow_mut().push(job).is_err() {
                session.ctx.fail_queue_full(sid);
            }
        }

        let sched_fut = {
            let s = session.clone();
            async move { s.scheduler_loop(Rc::new(Cell::new(true))).await }
        };
        let hub_fut = async move { hub.run().await };
        ctx.wait_until(sched_fut);
        ctx.wait_until(hub_fut);
        return wisp_response(&cfg, out_rx);
    }

    countup("not_found");
    json_error(404, "not found")
}
