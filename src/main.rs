use hmac::{Hmac, Mac};
use if_addrs::get_if_addrs;
use md5::{Digest, Md5};
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::interval;

type HmacSha256 = Hmac<Sha256>;
const APP_NAME: &str = "PySIP/1.0.1-Rust";
const DEFAULT_REALM: &str = "pysip.local";
const DEFAULT_DB: &str = "pysip.db";
const SIP_PORT: u16 = 5060;
const MAX_PACKET: usize = 32_768;
const MAX_HEADER_BYTES: usize = 16_384;
const MAX_REGISTRATION_SECS: u64 = 3_600;
const DEFAULT_REGISTRATION_SECS: u64 = 900;
const NONCE_TTL_SECS: u64 = 300;
const TRANSACTION_TTL_SECS: u64 = 180;
const INVITE_RING_TIMEOUT_SECS: u64 = 60;
const MAX_ACTIVE_CALLS: usize = 64;
const MAX_TRANSACTIONS: usize = 4_096;
const MAX_DEVICES_PER_ACCOUNT: usize = 16;
const CALL_HISTORY_LIMIT: usize = 500;
const RTP_MIN_DEFAULT: u16 = 20_000;
const RTP_MAX_DEFAULT: u16 = 30_000;

const SIP_METHODS: &[&str] = &[
    "INVITE", "ACK", "CANCEL", "BYE", "REGISTER", "OPTIONS", "PRACK", "SUBSCRIBE",
    "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE",
];

#[derive(Clone)]
struct Config {
    db_path: PathBuf,
    realm: String,
    listen_ip: IpAddr,
    listen_port: u16,
    advertised_ip: IpAddr,
    rtp_min: u16,
    rtp_max: u16,
}

#[derive(Clone, Debug)]
struct SipMessage {
    method: String,
    uri: String,
    start_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    is_response: bool,
    status: u16,
    reason: String,
}

impl SipMessage {
    fn header(&self, name: &str) -> String {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone()).unwrap_or_default()
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone()).collect()
    }
    fn cseq(&self) -> Option<u32> {
        let value = self.header("cseq");
        let mut parts = value.split_whitespace();
        let number = parts.next()?;
        let method = parts.next()?;
        if parts.next().is_none() && !method.is_empty() { number.parse().ok() } else { None }
    }
    fn cseq_method(&self) -> String {
        self.header("cseq").split_whitespace().nth(1).unwrap_or("").to_ascii_uppercase()
    }
}

fn canonical_header(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "v" => "via", "f" => "from", "t" => "to", "i" => "call-id", "m" => "contact",
        "l" => "content-length", "c" => "content-type", "s" => "subject", "k" => "supported",
        "o" => "event", "r" => "refer-to", "b" => "referred-by", "u" => "allow-events",
        other => other,
    }.to_string()
}

fn parse_sip(data: &[u8]) -> Result<Option<SipMessage>, String> {
    if data.len() > MAX_PACKET { return Err("SIP datagram too large".into()); }
    let mut start = 0;
    while start + 1 < data.len() && data[start..].starts_with(b"\r\n") { start += 2; }
    if start >= data.len() { return Ok(None); }
    let data = &data[start..];
    if data.iter().all(|b| *b == b'\r' || *b == b'\n') { return Ok(None); }
    let (head_end, sep_len) = if let Some(i) = find_bytes(data, b"\r\n\r\n") { (i, 4) }
        else if let Some(i) = find_bytes(data, b"\n\n") { (i, 2) }
        else { return Err("missing SIP header separator".into()); };
    if head_end > MAX_HEADER_BYTES { return Err("SIP headers too large".into()); }
    let head = String::from_utf8_lossy(&data[..head_end]);
    let mut lines: Vec<String> = head.replace("\r\n", "\n").split('\n').map(|s| s.to_string()).collect();
    if lines.is_empty() || lines[0].trim().is_empty() { return Err("missing SIP start line".into()); }
    if lines.len() > 130 { return Err("too many SIP headers".into()); }
    let start_line = lines.remove(0).trim().to_string();
    let (is_response, method, uri, status, reason) = if start_line.starts_with("SIP/2.0 ") {
        let mut p = start_line.splitn(3, ' ');
        let _ = p.next();
        let code: u16 = p.next().ok_or("invalid response line")?.parse().map_err(|_| "invalid status code")?;
        if !(100..=699).contains(&code) { return Err("invalid SIP status code".into()); }
        (true, String::new(), String::new(), code, p.next().unwrap_or("").to_string())
    } else {
        let p: Vec<&str> = start_line.split_whitespace().collect();
        if p.len() != 3 || p[2] != "SIP/2.0" { return Err("invalid SIP request line".into()); }
        if p[0].len() > 32 || p[1].len() > 2_048 { return Err("SIP request line too long".into()); }
        if !p[0].bytes().all(|b| b.is_ascii_alphanumeric() || b".!%*_+`'~-".contains(&b)) { return Err("invalid SIP method".into()); }
        (false, p[0].to_ascii_uppercase(), p[1].to_string(), 0, String::new())
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() { continue; }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() { last.1.push(' '); last.1.push_str(line.trim()); }
            else { return Err("orphan folded SIP header".into()); }
            continue;
        }
        let (name, value) = line.split_once(':').ok_or("malformed SIP header")?;
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') { return Err("invalid SIP header name".into()); }
        let value: String = value.trim().chars().filter(|c| !c.is_control() || *c == '\t').collect();
        headers.push((canonical_header(name), value));
    }
    let body_start = head_end + sep_len;
    let body = data[body_start..].to_vec();
    let lengths: Vec<usize> = headers.iter().filter(|(k, _)| k == "content-length")
        .map(|(_, v)| v.parse::<usize>().map_err(|_| "invalid Content-Length"))
        .collect::<Result<Vec<_>, _>>()?;
    if !lengths.is_empty() {
        if lengths.iter().any(|n| *n != lengths[0]) { return Err("conflicting Content-Length headers".into()); }
        if lengths[0] != body.len() || lengths[0] > MAX_PACKET { return Err("Content-Length mismatch".into()); }
    } else if !body.is_empty() { return Err("missing Content-Length".into()); }
    for required in ["via", "from", "to", "call-id", "cseq"] {
        if !headers.iter().any(|(k, v)| k == required && !v.is_empty()) { return Err(format!("missing required header: {required}")); }
    }
    let cseq = headers.iter().find(|(k, _)| k == "cseq").map(|(_, v)| v.as_str()).unwrap_or("");
    let cparts: Vec<&str> = cseq.split_whitespace().collect();
    if cparts.len() != 2 || cparts[0].parse::<u32>().map(|n|n>2_147_483_647).unwrap_or(true) { return Err("invalid CSeq".into()); }
    if !is_response && cparts[1].to_ascii_uppercase() != method { return Err("CSeq method mismatch".into()); }
    Ok(Some(SipMessage { method: if is_response { cparts[1].to_ascii_uppercase() } else { method }, uri, start_line, headers, body, is_response, status, reason }))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
fn md5_hex(value: &str) -> String { format!("{:x}", Md5::digest(value.as_bytes())) }
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
fn get_uri_user(value: &str) -> String {
    let uri = if let (Some(l), Some(r)) = (value.find('<'), value.find('>')) { &value[l + 1..r] } else { value.trim() };
    let uri = uri.strip_prefix("sips:").or_else(|| uri.strip_prefix("SIPS:")).or_else(|| uri.strip_prefix("sip:")).or_else(|| uri.strip_prefix("SIP:")).unwrap_or(uri);
    let user = uri.split('@').next().unwrap_or("").split(';').next().unwrap_or("").split('?').next().unwrap_or("");
    user.replace("%2B", "+").replace("%2b", "+")
}
fn normalize_phone(s: &str) -> String {
    let compact: String = s.chars().filter(|c| !c.is_whitespace() && !"().-".contains(*c)).collect();
    if compact.starts_with('+') { compact } else if compact.chars().all(|c| c.is_ascii_digit()) && compact.len() >= 7 { format!("+{compact}") } else { compact }
}
fn rewrite_uri_hosts(value: &str, host: &str, port: Option<u16>) -> String {
    let re = Regex::new(r"(?i)(sips?:[^@<>\s]+@)(\[[^\]]+\]|[^:;>\s]+)(?::(\d+))?").unwrap();
    let safe_host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
    re.replace_all(value, |caps: &regex::Captures| {
        let p = port.map(|v| v.to_string()).or_else(|| caps.get(3).map(|m| m.as_str().to_string()));
        format!("{}{}{}", &caps[1], safe_host, p.map(|v| format!(":{v}")).unwrap_or_default())
    }).to_string()
}
fn split_header_values(value: &str) -> Vec<String> {
    let mut out = Vec::new(); let mut cur = String::new(); let mut quoted = false; let mut escaped = false; let mut angle = 0i32;
    for c in value.chars() {
        if escaped { cur.push(c); escaped = false; continue; }
        if c == '\\' && quoted { cur.push(c); escaped = true; continue; }
        if c == '"' { quoted = !quoted; }
        else if !quoted && c == '<' { angle += 1; }
        else if !quoted && c == '>' && angle > 0 { angle -= 1; }
        if c == ',' && !quoted && angle == 0 { if !cur.trim().is_empty() { out.push(cur.trim().to_string()); } cur.clear(); }
        else { cur.push(c); }
    }
    if !cur.trim().is_empty() { out.push(cur.trim().to_string()); }
    out
}
fn contact_uri_expires(value: &str) -> Result<(String, Option<u64>), String> {
    let expires_re = Regex::new(r"(?i)(?:^|;)\s*expires\s*=\s*([^;>\s,]+)").unwrap();
    let expires = expires_re.captures(value).map(|c| c[1].parse::<u64>().map_err(|_| "bad Contact expires".to_string())).transpose()?;
    let uri = if let Some(c) = Regex::new(r"<([^>]+)>").unwrap().captures(value) { c[1].trim().to_string() } else { value.split(';').next().unwrap_or("").trim().to_string() };
    Ok((uri, expires))
}
fn parse_digest(value: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let trimmed=value.trim();
    let payload=if trimmed.get(..7).map(|v|v.eq_ignore_ascii_case("Digest ")).unwrap_or(false){&trimmed[7..]}else{""};
    let mut cur = String::new(); let mut quoted = false; let mut escaped = false;
    let mut parts = Vec::new();
    for c in payload.chars() {
        if escaped { cur.push(c); escaped = false; continue; }
        if c == '\\' && quoted { cur.push(c); escaped = true; continue; }
        if c == '"' { quoted = !quoted; }
        if c == ',' && !quoted { parts.push(cur.clone()); cur.clear(); } else { cur.push(c); }
    }
    if !cur.is_empty() { parts.push(cur); }
    for part in parts { if let Some((k,v)) = part.split_once('=') {
        let key = k.trim().to_ascii_lowercase(); let mut val = v.trim().to_string();
        if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 { val = val[1..val.len()-1].replace("\\\"", "\"").replace("\\\\", "\\"); }
        out.insert(key, val);
    }}
    out
}

struct NonceManager { secret: [u8;32], nc: HashMap<(String,String,String), (u32,u64)> }
impl NonceManager {
    fn new() -> Self { let mut secret=[0u8;32]; OsRng.fill_bytes(&mut secret); Self { secret, nc: HashMap::new() } }
    fn issue(&self) -> String {
        let payload = format!("{}:{}", now_secs(), random_hex(12));
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC key"); mac.update(payload.as_bytes());
        format!("{}.{}", payload, hex::encode(mac.finalize().into_bytes()))
    }
    fn validate(&self, nonce: &str) -> (bool,bool) {
        let Some((payload,sig)) = nonce.rsplit_once('.') else { return (false,false); };
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC key"); mac.update(payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        if !constant_time_eq(&expected, sig) { return (false,false); }
        let timestamp = payload.split(':').next().and_then(|v| v.parse::<u64>().ok());
        let Some(ts) = timestamp else { return (false,false); };
        let age = now_secs().saturating_sub(ts);
        if ts > now_secs() + 30 { return (false,false); }
        if age > NONCE_TTL_SECS { return (false,true); }
        (true,false)
    }
    fn record_nc(&mut self, username: &str, nonce: &str, cnonce: &str, nc: &str) -> bool {
        if nc.len() != 8 || !nc.bytes().all(|b| b.is_ascii_hexdigit()) { return false; }
        let Ok(value) = u32::from_str_radix(nc,16) else { return false; };
        let key=(username.to_ascii_lowercase(),nonce.to_string(),cnonce.to_string());
        if self.nc.get(&key).map(|v|v.0).unwrap_or(0) >= value { return false; }
        let now=now_secs(); self.nc.insert(key,(value,now));
        if self.nc.len()>10_000 { self.nc.retain(|_,(_,seen)|now.saturating_sub(*seen)<=NONCE_TTL_SECS); }
        true
    }
}
fn random_hex(bytes: usize) -> String { let mut data=vec![0u8;bytes]; OsRng.fill_bytes(&mut data); hex::encode(data) }
fn now_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

#[derive(Clone, Debug)]
struct User { id:i64, username:String, phone:String, enabled:bool, ha1:String }
#[derive(Clone, Debug)]
struct Device { contact:String, ip:IpAddr, port:u16, user_agent:String, expires:u64 }
fn db_connect(cfg:&Config) -> Result<Connection,String> {
    let c=Connection::open(&cfg.db_path).map_err(|e|e.to_string())?;
    c.busy_timeout(Duration::from_secs(10)).map_err(|e|e.to_string())?;
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;").map_err(|e|e.to_string())?;
    Ok(c)
}
fn ensure_schema(cfg:&Config) -> Result<(),String> {
    let c=db_connect(cfg)?;
    c.execute_batch("PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,sip_ha1 TEXT NOT NULL,phone_number TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS registrations(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,contact TEXT NOT NULL,expires_at INTEGER NOT NULL,source_ip TEXT NOT NULL,source_port INTEGER NOT NULL,user_agent TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS sip_contacts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,contact_uri TEXT NOT NULL,source_ip TEXT NOT NULL,source_port INTEGER NOT NULL,user_agent TEXT NOT NULL DEFAULT '',expires_at INTEGER NOT NULL,call_id TEXT NOT NULL DEFAULT '',cseq INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL,UNIQUE(user_id,contact_uri));
    CREATE INDEX IF NOT EXISTS idx_sip_contacts_user_expiry ON sip_contacts(user_id,expires_at DESC,updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sip_contacts_endpoint ON sip_contacts(source_ip,source_port,expires_at);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS calls(call_id TEXT PRIMARY KEY,caller_username TEXT NOT NULL,callee_username TEXT NOT NULL,caller_number TEXT NOT NULL DEFAULT '',callee_number TEXT NOT NULL DEFAULT '',state TEXT NOT NULL,detail TEXT NOT NULL DEFAULT '',sip_code INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,caller_ip TEXT NOT NULL DEFAULT '',caller_port INTEGER NOT NULL DEFAULT 0,callee_ip TEXT NOT NULL DEFAULT '',callee_port INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_calls_updated ON calls(updated_at DESC);
    INSERT OR IGNORE INTO sip_contacts(user_id,contact_uri,source_ip,source_port,user_agent,expires_at,call_id,cseq,updated_at)
      SELECT user_id,contact,source_ip,source_port,user_agent,expires_at,'',0,updated_at FROM registrations WHERE expires_at > strftime('%s','now');").map_err(|e|e.to_string())?;
    Ok(())
}
fn persist_advertised_host(cfg:&Config) -> Result<(),String> {
    let c=db_connect(cfg)?; c.execute("INSERT INTO settings(key,value) VALUES('advertised_host',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[cfg.advertised_ip.to_string()]).map_err(|e|e.to_string())?; Ok(())
}
fn find_user(cfg:&Config, identity:&str, require_devices:bool) -> Result<Option<(User,Vec<Device>)>,String> {
    let identity=identity.trim(); let phone=normalize_phone(identity); let c=db_connect(cfg)?;
    let row: Option<User> = c.query_row("SELECT id,username,phone_number,enabled,sip_ha1 FROM users WHERE username=?1 COLLATE NOCASE OR phone_number=?2 LIMIT 1",params![identity,phone],|r|Ok(User{id:r.get(0)?,username:r.get(1)?,phone:r.get(2)?,enabled:r.get::<_,i64>(3)?!=0,ha1:r.get(4)?})).optional().map_err(|e|e.to_string())?;
    let Some(user)=row else { return Ok(None); }; if !user.enabled { return Ok(None); }
    let mut devices=Vec::new();
    {
        let mut s=c.prepare("SELECT contact_uri,source_ip,source_port,user_agent,expires_at FROM sip_contacts WHERE user_id=?1 AND expires_at>?2 ORDER BY updated_at DESC LIMIT 16").map_err(|e|e.to_string())?;
        let rows=s.query_map(params![user.id,now_secs() as i64],|r| {
            let ip:String=r.get(1)?; let addr=ip.parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            Ok(Device{contact:r.get(0)?,ip:addr,port:r.get::<_,i64>(2)?.clamp(1,65535) as u16,user_agent:r.get(3)?,expires:r.get::<_,i64>(4)?.max(0) as u64})
        }).map_err(|e|e.to_string())?;
        for item in rows { devices.push(item.map_err(|e|e.to_string())?); }
    }
    if devices.is_empty() {
        let legacy: Option<Device> = c.query_row("SELECT contact,source_ip,source_port,user_agent,expires_at FROM registrations WHERE user_id=?1 AND expires_at>?2",params![user.id,now_secs() as i64],|r| {
            let ip:String=r.get(1)?; Ok(Device{contact:r.get(0)?,ip:ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),port:r.get::<_,i64>(2)?.clamp(1,65535) as u16,user_agent:r.get(3)?,expires:r.get::<_,i64>(4)?.max(0) as u64})
        }).optional().map_err(|e|e.to_string())?;
        if let Some(d)=legacy { devices.push(d); }
    }
    if require_devices && devices.is_empty() { return Ok(None); }
    Ok(Some((user,devices)))
}
fn source_registered(cfg:&Config,user_id:i64,source:SocketAddr)->Result<bool,String> {
    let c=db_connect(cfg)?; let ip=source.ip().to_string();
    let a:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sip_contacts WHERE user_id=?1 AND source_ip=?2 AND source_port=?3 AND expires_at>?4)",params![user_id,ip,source.port(),now_secs() as i64],|r|r.get(0)).map_err(|e|e.to_string())?;
    if a { return Ok(true); }
    c.query_row("SELECT EXISTS(SELECT 1 FROM registrations WHERE user_id=?1 AND source_ip=?2 AND source_port=?3 AND expires_at>?4)",params![user_id,ip,source.port(),now_secs() as i64],|r|r.get(0)).map_err(|e|e.to_string())
}
fn record_call(cfg:&Config,msg:&SipMessage,caller:&User,callee:Option<&User>,state:&str,detail:&str,code:u16,source:SocketAddr,target:Option<SocketAddr>) {
    let call_id=msg.header("call-id"); if call_id.is_empty(){return;}
    let to_number=callee.map(|u|u.phone.clone()).unwrap_or_else(||get_uri_user(&msg.uri));
    if let Ok(c)=db_connect(cfg) {
        let _=c.execute("INSERT INTO calls(call_id,caller_username,callee_username,caller_number,callee_number,state,detail,sip_code,created_at,updated_at,caller_ip,caller_port,callee_ip,callee_port) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10,?11,?12,?13) ON CONFLICT(call_id) DO UPDATE SET state=excluded.state,detail=excluded.detail,sip_code=excluded.sip_code,updated_at=excluded.updated_at,callee_ip=excluded.callee_ip,callee_port=excluded.callee_port",params![call_id,caller.username,callee.map(|u|u.username.as_str()).unwrap_or("unknown"),caller.phone,to_number,state,detail.chars().take(300).collect::<String>(),code,now_secs() as i64,source.ip().to_string(),source.port(),target.map(|x|x.ip().to_string()).unwrap_or_default(),target.map(|x|x.port()).unwrap_or(0)]);
        let _=c.execute("DELETE FROM calls WHERE call_id IN (SELECT call_id FROM calls ORDER BY updated_at DESC LIMIT -1 OFFSET ?1)",[CALL_HISTORY_LIMIT as i64]);
    }
}
fn set_call_state(cfg:&Config,call_id:&str,state:&str,detail:&str,code:u16) {
    if let Ok(c)=db_connect(cfg) { let _=c.execute("UPDATE calls SET state=?1,detail=?2,sip_code=?3,updated_at=?4 WHERE call_id=?5",params![state,detail.chars().take(300).collect::<String>(),code,now_secs() as i64,call_id]); }
}

#[derive(Clone)]
struct Outbound { data:Vec<u8>, target:SocketAddr }
#[derive(Clone)]
struct Transaction { branch:String, original_branch:String, call_id:String, cseq:u32, method:String, callee:String, source:SocketAddr, target:SocketAddr, forwarded_uri:String, forwarded_invite:Vec<u8>, original:SipMessage, final_seen:bool, expires:u64 }
#[derive(Clone)]
struct FinalResponse { code:u16, msg:SipMessage, branch:String, fallback:bool }
struct Fork { call_id:String, cseq:u32, source:SocketAddr, caller:String, callee:String, branches:Vec<String>, winner:Option<String>, finals:Vec<FinalResponse>, cancelled:bool, final_sent:bool, original:SipMessage, final_tx:Option<String>, expires:u64 }
struct Dialog { caller:String, callee:String, caller_ep:SocketAddr, callee_ep:Option<SocketAddr>, state:String, expires:u64 }
struct ServerState {
    nonce:NonceManager,
    transactions:HashMap<String,Transaction>,
    forks:HashMap<(String,u32),Fork>,
    dialogs:HashMap<String,Dialog>,
    tags:HashMap<String,String>,
    relays:HashMap<String,RtpRelayPair>,
    rate:HashMap<IpAddr,(Instant,u32)>,
}
impl ServerState { fn new()->Self { Self{nonce:NonceManager::new(),transactions:HashMap::new(),forks:HashMap::new(),dialogs:HashMap::new(),tags:HashMap::new(),relays:HashMap::new(),rate:HashMap::new()} } }

#[derive(Clone,Default)]
struct RelayTargets { caller_ip:Option<IpAddr>, callee_ip:Option<IpAddr>, caller_rtp:Option<SocketAddr>, caller_rtcp:Option<SocketAddr>, callee_rtp:Option<SocketAddr>, callee_rtcp:Option<SocketAddr> }
struct RtpRelayPair { caller_rtp:u16, caller_rtcp:u16, callee_rtp:u16, callee_rtcp:u16, targets:Arc<Mutex<RelayTargets>>, tasks:Vec<JoinHandle<()>> }
impl RtpRelayPair {
    async fn new(cfg:&Config,caller:SocketAddr,offered:SDPAudio,callee_ips:Vec<IpAddr>)->Result<Self,String> {
        let targets=Arc::new(Mutex::new(RelayTargets{caller_ip:Some(caller.ip()),callee_ip:callee_ips.first().copied(),caller_rtp:Some(SocketAddr::new(caller.ip(),offered.rtp)),caller_rtcp:Some(SocketAddr::new(caller.ip(),offered.rtcp)),..Default::default()}));
        let mut sockets=Vec::new(); let mut ports=Vec::new();
        for _ in 0..4 { let (sock,port)=bind_udp_range(cfg.rtp_min,cfg.rtp_max).await?; sockets.push(Arc::new(sock)); ports.push(port); }
        let mut tasks=Vec::new();
        let labels=[("caller","rtp"),("caller","rtcp"),("callee","rtp"),("callee","rtcp")];
        for (idx,sock) in sockets.into_iter().enumerate() {
            let targets2=targets.clone(); let side=labels[idx].0.to_string(); let kind=labels[idx].1.to_string();
            tasks.push(tokio::spawn(async move { relay_loop(sock,targets2,side,kind).await; }));
        }
        Ok(Self{caller_rtp:ports[0],caller_rtcp:ports[1],callee_rtp:ports[2],callee_rtcp:ports[3],targets,tasks})
    }
    async fn set_callee_peer(&self,ip:IpAddr,rtp:u16,rtcp:u16) { let mut t=self.targets.lock().await; t.callee_ip=Some(ip); t.callee_rtp=Some(SocketAddr::new(ip,rtp)); t.callee_rtcp=Some(SocketAddr::new(ip,rtcp)); }
    fn close(&mut self) { for h in self.tasks.drain(..) { h.abort(); } }
}
async fn bind_udp_range(min:u16,max:u16)->Result<(UdpSocket,u16),String> {
    if min<1024 || min>=max { return Err("invalid RTP port range".into()); }
    for _ in 0..250 { let span=(max-min) as u32; let p=min+(rand::random::<u32>()%(span+1)) as u16;
        if let Ok(s)=UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED),p)).await { return Ok((s,p)); }
    }
    Err(format!("could not allocate RTP port in {min}-{max}"))
}
async fn relay_loop(socket:Arc<UdpSocket>,targets:Arc<Mutex<RelayTargets>>,side:String,kind:String) {
    let mut buf=vec![0u8;65_535];
    loop {
        let (n,from)=match socket.recv_from(&mut buf).await { Ok(v)=>v,Err(_)=>break };
        if n<4 || buf[0]>>6!=2 { continue; }
        let mut t=targets.lock().await;
        let expected=if side=="caller" {t.caller_ip} else {t.callee_ip};
        if expected!=Some(from.ip()) { continue; }
        let destination=if side=="caller" {
            if kind=="rtp" { t.caller_rtp=Some(from); t.callee_rtp } else { t.caller_rtcp=Some(from); t.callee_rtcp }
        } else if kind=="rtp" { t.callee_rtp=Some(from); t.caller_rtp } else { t.callee_rtcp=Some(from); t.caller_rtcp };
        drop(t);
        if let Some(to)=destination { let _=socket.send_to(&buf[..n],to).await; }
    }
}
#[derive(Clone,Copy)] struct SDPAudio { rtp:u16,rtcp:u16 }
fn parse_sdp_audio(body:&[u8])->Result<SDPAudio,String> {
    let text=String::from_utf8_lossy(body);
    let normalized=text.replace("\r\n","\n");
    let lines:Vec<String>=normalized.lines().map(|s|s.trim().to_string()).collect();
    for (i,line) in lines.iter().enumerate() { if line.to_ascii_lowercase().starts_with("m=audio ") {
        let fields:Vec<&str>=line.split_whitespace().collect(); if fields.len()<4{return Err("malformed SDP audio line".into());}
        let rtp=fields[1].split('/').next().unwrap_or("").parse::<u16>().map_err(|_|"bad SDP RTP port")?; if rtp==0{return Err("inactive SDP audio".into());}
        let end=lines.iter().enumerate().skip(i+1).find(|(_,l)|l.starts_with("m=")).map(|(j,_)|j).unwrap_or(lines.len());
        let rtcp=lines[i+1..end].iter().find_map(|l|l.strip_prefix("a=rtcp:").and_then(|v|v.split_whitespace().next()).and_then(|v|v.parse::<u16>().ok())).unwrap_or(rtp.saturating_add(1));
        if rtcp==0{return Err("bad SDP RTCP port".into());} return Ok(SDPAudio{rtp,rtcp});
    }} Err("SDP has no audio media".into())
}
fn rewrite_sdp(body:&[u8],rtp:u16,rtcp:u16,host:IpAddr)->Result<Vec<u8>,String> {
    parse_sdp_audio(body)?;
    let normalized=String::from_utf8_lossy(body).replace("\r\n","\n");
    let mut lines:Vec<String>=normalized.lines().map(|s|s.to_string()).collect();
    let start=lines.iter().position(|l|l.to_ascii_lowercase().starts_with("m=audio ")).ok_or("missing audio m-line")?;
    let end=lines.iter().enumerate().skip(start+1).find(|(_,l)|l.starts_with("m=")).map(|(i,_)|i).unwrap_or(lines.len());
    let mut fields:Vec<String>=lines[start].split_whitespace().map(str::to_string).collect(); fields[1]=rtp.to_string(); lines[start]=fields.join(" ");
    // Keep codec/fmtp/ptime attributes. Replace only connection/RTCP details;
    // remove rtcp-mux so clients use the separately advertised RTCP port.
    let mut idx=end;
    while idx>start+1 { idx-=1; let lower=lines[idx].to_ascii_lowercase();
        if lower.starts_with("c=") || lower.starts_with("a=rtcp:") || lower=="a=rtcp-mux" { lines.remove(idx); }
    }
    lines.insert(start+1,format!("c=IN IP4 {host}"));
    lines.insert(start+2,format!("a=rtcp:{rtcp} IN IP4 {host}"));
    Ok(format!("{}\r\n",lines.join("\r\n")).into_bytes())
}

fn build_response(msg:&SipMessage,code:u16,reason:&str,source:SocketAddr,state:&mut ServerState)->Vec<u8> {
    let mut lines=vec![format!("SIP/2.0 {code} {reason}")];
    for via in msg.all("via") { let mut v=via.clone();
        if Regex::new(r"(?i);rport(?:=\d+)?(?:;|$)").unwrap().is_match(&v) {
            if !v.to_ascii_lowercase().contains(";received=") { v.push_str(&format!(";received={}",source.ip())); }
            v=Regex::new(r"(?i);rport(?:=\d+)?").unwrap().replace(&v,format!(";rport={}",source.port())).to_string();
        } lines.push(format!("Via: {v}"));
    }
    for name in ["from","to","call-id","cseq"] { let mut value=msg.header(name); if value.is_empty(){continue;}
        if name=="to" && code!=100 && !value.to_ascii_lowercase().contains(";tag=") { let tag=state.tags.entry(msg.header("call-id")).or_insert_with(||random_hex(6)).clone(); value.push_str(&format!(";tag={tag}")); }
        let display=match name {"call-id"=>"Call-ID","cseq"=>"CSeq","from"=>"From",_=>"To"}; lines.push(format!("{display}: {value}"));
    }
    lines.push(format!("Server: {APP_NAME}")); lines.push(format!("Allow: {}",SIP_METHODS.join(", "))); lines.push("Content-Length: 0".into()); lines.push(String::new()); lines.push(String::new()); lines.join("\r\n").into_bytes()
}
fn append_headers(mut response:Vec<u8>,headers:&[String])->Vec<u8> {
    let text=String::from_utf8_lossy(&response).to_string(); let (head,tail)=text.split_once("\r\n\r\n").unwrap_or((&text,""));
    let mut new=head.trim_end_matches("\r\n").to_string(); for h in headers { new.push_str("\r\n");new.push_str(h); } new.push_str("\r\n\r\n"); new.push_str(tail); response=new.into_bytes();response
}
fn serialize_request(msg:&SipMessage,branch:&str,host:IpAddr,port:u16,record_route:bool,body_override:Option<&[u8]>,uri_override:Option<&str>)->Vec<u8> {
    let uri=uri_override.map(str::to_string).unwrap_or_else(||rewrite_uri_hosts(&msg.uri,&host.to_string(),Some(port)));
    let mut lines=vec![format!("{} {} SIP/2.0",msg.method,uri),format!("Via: SIP/2.0/UDP {host}:{port};branch={branch};rport")];
    if record_route { lines.push(format!("Record-Route: <sip:{host}:{port};lr>")); }
    let mut max_seen=false;
    for (name,value) in &msg.headers {
        match name.as_str() {
            "via"=>lines.push(format!("Via: {value}")),
            "route"=>{let remaining=remove_own_route(value,host,port);if !remaining.is_empty(){lines.push(format!("Route: {remaining}"));}},
            "content-length"=>{},
            "max-forwards"=>{max_seen=true;let n=value.parse::<i32>().unwrap_or(70)-1;lines.push(format!("Max-Forwards: {}",n.max(0)));},
            "from"|"to"=>lines.push(format!("{}: {}",display_header(name),rewrite_uri_hosts(value,&host.to_string(),None))),
            "contact"=>lines.push(format!("Contact: {}",rewrite_uri_hosts(value,&host.to_string(),Some(port)))),
            _=>lines.push(format!("{}: {}",display_header(name),value)),
        }
    }
    if !max_seen { lines.push("Max-Forwards: 69".into()); }
    let body=body_override.unwrap_or(&msg.body); lines.push(format!("Content-Length: {}",body.len()));
    let mut out=(lines.join("\r\n").to_string()+"\r\n\r\n").into_bytes();out.extend_from_slice(body);out
}
fn serialize_response(msg:&SipMessage,host:IpAddr,port:u16,body_override:Option<&[u8]>)->Vec<u8> {
    let mut lines=vec![msg.start_line.clone()];
    for (name,value) in &msg.headers {
        if name=="content-length" {continue;}
        if name=="via" {
            for via in split_header_values(value) { let own=via.to_ascii_lowercase().contains(&format!("{host}:{port}")) && via.contains("z9hG4bK-pysip-"); if !own {lines.push(format!("Via: {via}"));} }
        } else if name=="from"||name=="to" {lines.push(format!("{}: {}",display_header(name),rewrite_uri_hosts(value,&host.to_string(),None)));}
        else if name=="contact" {lines.push(format!("Contact: {}",rewrite_uri_hosts(value,&host.to_string(),Some(port))));}
        else {lines.push(format!("{}: {}",display_header(name),value));}
    }
    let body=body_override.unwrap_or(&msg.body);lines.push(format!("Content-Length: {}",body.len()));let mut out=(lines.join("\r\n")+"\r\n\r\n").into_bytes();out.extend_from_slice(body);out
}
fn display_header(n:&str)->String { match n {"call-id"=>"Call-ID".into(),"cseq"=>"CSeq".into(),"content-type"=>"Content-Type".into(),"content-length"=>"Content-Length".into(),"max-forwards"=>"Max-Forwards".into(),"record-route"=>"Record-Route".into(),"user-agent"=>"User-Agent".into(),_=>n.split('-').map(|p|{let mut c=p.chars();c.next().map(|x|x.to_ascii_uppercase().to_string()+c.as_str()).unwrap_or_default()}).collect::<Vec<_>>().join("-")} }
fn remove_own_route(value:&str,host:IpAddr,port:u16)->String { let mut p=split_header_values(value); if !p.is_empty() && p[0].to_ascii_lowercase().contains(&format!("sip:{host}:{port}")){p.remove(0);}p.join(", ") }
fn dialog_uri(username:&str,endpoint:SocketAddr)->String {format!("sip:{}@{}:{}",username,endpoint.ip(),endpoint.port())}
fn branch_from_via(msg:&SipMessage)->String { let v=msg.header("via"); Regex::new(r"(?i);branch=([^;\s,]+)").unwrap().captures(&v).map(|c|c[1].to_string()).unwrap_or_default() }

fn get_devices(cfg:&Config,user_id:i64)->Result<Vec<Device>,String> {
    let c=db_connect(cfg)?;let mut s=c.prepare("SELECT contact_uri,source_ip,source_port,user_agent,expires_at FROM sip_contacts WHERE user_id=?1 AND expires_at>?2 ORDER BY updated_at DESC LIMIT 16").map_err(|e|e.to_string())?;
    let mut out=Vec::new();let rows=s.query_map(params![user_id,now_secs() as i64],|r|{let ip:String=r.get(1)?;Ok(Device{contact:r.get(0)?,ip:ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),port:r.get::<_,i64>(2)?.clamp(1,65535) as u16,user_agent:r.get(3)?,expires:r.get::<_,i64>(4)?.max(0) as u64})}).map_err(|e|e.to_string())?;
    for r in rows{out.push(r.map_err(|e|e.to_string())?);}if out.is_empty(){let d:Option<Device>=c.query_row("SELECT contact,source_ip,source_port,user_agent,expires_at FROM registrations WHERE user_id=?1 AND expires_at>?2",params![user_id,now_secs() as i64],|r|{let ip:String=r.get(1)?;Ok(Device{contact:r.get(0)?,ip:ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),port:r.get::<_,i64>(2)?.clamp(1,65535) as u16,user_agent:r.get(3)?,expires:r.get::<_,i64>(4)?.max(0) as u64})}).optional().map_err(|e|e.to_string())?;if let Some(x)=d{out.push(x);}}Ok(out)
}
fn registered_source(cfg:&Config,user_id:i64,source:SocketAddr)->bool { source_registered(cfg,user_id,source).unwrap_or(false) }
fn choose_callee(cfg:&Config,msg:&SipMessage)->Result<Option<(User,Vec<Device>)>,String> {
    for ident in [get_uri_user(&msg.uri),get_uri_user(&msg.header("to"))] { if ident.is_empty(){continue;} if let Some((user,_))=find_user(cfg,&ident,false)? {let devices=get_devices(cfg,user.id)?;return Ok(Some((user,devices)));} }
    Ok(None)
}
fn validate_caller(cfg:&Config,msg:&SipMessage,source:SocketAddr)->Result<Option<User>,String> {
    let name=get_uri_user(&msg.header("from"));let Some((user,_))=find_user(cfg,&name,true)? else{return Ok(None)}; if !registered_source(cfg,user.id,source){return Ok(None);} Ok(Some(user))
}

async fn handle_register(msg:&SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound> {
    let to_name=get_uri_user(&msg.header("to"));let auth=parse_digest(&msg.header("authorization"));
    if auth.is_empty(){return vec![Outbound{data:challenge(msg,source,cfg,state,false),target:source}];}
    let username=auth.get("username").cloned().unwrap_or_default();let realm=auth.get("realm").cloned().unwrap_or_default();let nonce=auth.get("nonce").cloned().unwrap_or_default();let uri=auth.get("uri").cloned().unwrap_or_default();let response=auth.get("response").cloned().unwrap_or_default();let qop=auth.get("qop").cloned().unwrap_or_default().to_ascii_lowercase();let nc=auth.get("nc").cloned().unwrap_or_default();let cnonce=auth.get("cnonce").cloned().unwrap_or_default();let algorithm=auth.get("algorithm").cloned().unwrap_or_else(||"MD5".into()).to_ascii_uppercase();
    if to_name.is_empty()||username.is_empty()||realm!=cfg.realm||uri!=msg.uri{return one_response(msg,403,"Forbidden",source,state);}
    if algorithm!="MD5"||qop!="auth"||cnonce.is_empty(){return vec![Outbound{data:challenge(msg,source,cfg,state,false),target:source}];}
    let (valid,stale)=state.nonce.validate(&nonce);if !valid{return vec![Outbound{data:challenge(msg,source,cfg,state,stale),target:source}];}
    let user = match db_connect(cfg).and_then(|c|c.query_row("SELECT id,username,phone_number,enabled,sip_ha1 FROM users WHERE username=?1 COLLATE NOCASE OR phone_number=?1 LIMIT 1",[to_name.as_str()],|r|Ok(User{id:r.get(0)?,username:r.get(1)?,phone:r.get(2)?,enabled:r.get::<_,i64>(3)?!=0,ha1:r.get(4)?})).optional().map_err(|e|e.to_string())) {Ok(Some(u))=>u,_=>return one_response(msg,403,"Forbidden",source,state)};
    if username.to_ascii_lowercase()!=user.username.to_ascii_lowercase(){return one_response(msg,403,"Forbidden",source,state);}if !user.enabled{return one_response(msg,403,"Account Disabled",source,state);}
    let from=get_uri_user(&msg.header("from"));if !from.is_empty()&&from.to_ascii_lowercase()!=user.username.to_ascii_lowercase()&&from!=user.phone{return one_response(msg,403,"Forbidden",source,state);}
    let ha2=md5_hex(&format!("REGISTER:{uri}"));let expected=md5_hex(&format!("{}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}",user.ha1));if !constant_time_eq(&expected.to_ascii_lowercase(),&response.to_ascii_lowercase()){return vec![Outbound{data:challenge(msg,source,cfg,state,false),target:source}];}
    if !state.nonce.record_nc(&username,&nonce,&cnonce,&nc){return vec![Outbound{data:challenge(msg,source,cfg,state,true),target:source}];}
    let contact_headers=msg.all("contact");if contact_headers.is_empty(){return one_response(msg,400,"Missing Contact",source,state);}let contacts:Vec<String>=contact_headers.iter().flat_map(|h|split_header_values(h)).collect();if contacts.len()>16{return one_response(msg,400,"Too Many Contacts",source,state);}
    let expires_text=msg.header("expires");let parsed_expires=if expires_text.is_empty(){Ok(DEFAULT_REGISTRATION_SECS as i64)}else{expires_text.parse::<i64>().map_err(|_|())};let default_expires=match parsed_expires{Ok(v) if v>=0=>v as u64, _=>return one_response(msg,400,"Invalid Expires",source,state)}.min(MAX_REGISTRATION_SECS);
    if contacts.len()==1 && contacts[0]=="*" && default_expires!=0{return one_response(msg,400,"Wildcard Contact Requires Expires 0",source,state);}if contacts.iter().any(|c|c=="*")&&(contacts.len()!=1||default_expires!=0){return one_response(msg,400,"Wildcard Contact Requires Expires 0",source,state);}
    let mut parsed=Vec::new();for c in &contacts {let (uri,exp)=match contact_uri_expires(c){Ok(x)=>x,Err(_)=>return one_response(msg,400,"Invalid Contact",source,state)};if uri!="*"&&!(uri.to_ascii_lowercase().starts_with("sip:")||uri.to_ascii_lowercase().starts_with("sips:")){return one_response(msg,400,"Invalid Contact URI",source,state);}let expires=exp.unwrap_or(default_expires).min(MAX_REGISTRATION_SECS);parsed.push((uri,expires));}
    let now=now_secs() as i64;let cseq=msg.cseq().unwrap_or(0);let callid=msg.header("call-id");let ua=msg.header("user-agent");let mut response_contacts:Vec<String>=Vec::new();let c=match db_connect(cfg){Ok(c)=>c,Err(_)=>return one_response(msg,500,"Database Error",source,state)};
    if c.execute("BEGIN IMMEDIATE",[]).is_err(){return one_response(msg,500,"Database Busy",source,state);}
    for (contact,mut exp) in parsed {if contact=="*"{let _=c.execute("DELETE FROM sip_contacts WHERE user_id=?1",[user.id]);let _=c.execute("DELETE FROM registrations WHERE user_id=?1",[user.id]);continue;}if exp>0&&exp<60{exp=60;}
        let existing:Option<(String,i64)>=c.query_row("SELECT call_id,cseq FROM sip_contacts WHERE user_id=?1 AND contact_uri=?2",params![user.id,contact],|r|Ok((r.get(0)?,r.get(1)?))).optional().unwrap_or(None);
        if let Some((old_call,old_cseq))=existing{if old_call==callid&&cseq as i64<=old_cseq{let _=c.execute("ROLLBACK",[]);let mut out=one_response(msg,500,"CSeq Out of Order",source,state);let data=std::mem::take(&mut out[0].data);out[0].data=append_headers(data,&["Retry-After: 1".into()]);return out;}}
        if exp==0 {let _=c.execute("DELETE FROM sip_contacts WHERE user_id=?1 AND contact_uri=?2",params![user.id,contact]);continue;}
        let _=c.execute("INSERT INTO sip_contacts(user_id,contact_uri,source_ip,source_port,user_agent,expires_at,call_id,cseq,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(user_id,contact_uri) DO UPDATE SET source_ip=excluded.source_ip,source_port=excluded.source_port,user_agent=excluded.user_agent,expires_at=excluded.expires_at,call_id=excluded.call_id,cseq=excluded.cseq,updated_at=excluded.updated_at",params![user.id,contact,source.ip().to_string(),source.port(),ua.chars().take(256).collect::<String>(),now+exp as i64,callid,cseq,now]);
        response_contacts.push(format!("Contact: <{contact}>;expires={exp}"));
    }
    let latest:Option<(String,i64,String,i64,String,i64)>=c.query_row("SELECT contact_uri,expires_at,source_ip,source_port,user_agent,updated_at FROM sip_contacts WHERE user_id=?1 AND expires_at>?2 ORDER BY updated_at DESC LIMIT 1",params![user.id,now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().unwrap_or(None);
    if let Some((contact,exp,ip,port,useragent,updated))=latest {let _=c.execute("INSERT INTO registrations(user_id,contact,expires_at,source_ip,source_port,user_agent,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(user_id) DO UPDATE SET contact=excluded.contact,expires_at=excluded.expires_at,source_ip=excluded.source_ip,source_port=excluded.source_port,user_agent=excluded.user_agent,updated_at=excluded.updated_at",params![user.id,contact,exp,ip,port,useragent,updated]);}else{let _=c.execute("DELETE FROM registrations WHERE user_id=?1",[user.id]);}
    let _=c.execute("COMMIT",[]);
    println!("REGISTER {} from {} contacts={} user-agent={}",user.username,source,contacts.len(),ua.chars().take(100).collect::<String>());
    let mut additions=response_contacts;
    additions.push(format!("Expires: {}",default_expires.min(MAX_REGISTRATION_SECS)));
    let mut out=one_response(msg,200,"OK",source,state);let data=std::mem::take(&mut out[0].data);out[0].data=append_headers(data,&additions);out
}
fn challenge(msg:&SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState,stale:bool)->Vec<u8>{let nonce=state.nonce.issue();let hdr=format!("WWW-Authenticate: Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"{}",cfg.realm,nonce,if stale{", stale=true"}else{""});append_headers(build_response(msg,401,"Unauthorized",source,state),&[hdr])}
fn one_response(msg:&SipMessage,code:u16,reason:&str,source:SocketAddr,state:&mut ServerState)->Vec<Outbound>{vec![Outbound{data:build_response(msg,code,reason,source,state),target:source}]}

fn dialog_peer(state:&mut ServerState,callid:&str,sender:&str,cfg:&Config)->Option<(String,SocketAddr)> {
    let d=state.dialogs.get_mut(callid)?;let (peer,ep)=if sender.eq_ignore_ascii_case(&d.caller){(d.callee.clone(),d.callee_ep)}else if sender.eq_ignore_ascii_case(&d.callee){(d.caller.clone(),Some(d.caller_ep))}else{return None};
    let endpoint=ep.or_else(||find_user(cfg,&peer,true).ok().flatten().and_then(|(_,dev)|dev.first().map(|x|SocketAddr::new(x.ip,x.port))))?;d.expires=now_secs()+86_400;Some((peer,endpoint))
}
fn purge_call(state:&mut ServerState,callid:&str){state.dialogs.remove(callid);state.tags.remove(callid);state.forks.retain(|(id,_),_|id!=callid);state.transactions.retain(|_,t|t.call_id!=callid);if let Some(mut r)=state.relays.remove(callid){r.close();}}
fn make_cancel(tx:&Transaction,cfg:&Config)->Vec<u8>{
    let mut m=tx.original.clone();m.method="CANCEL".into();
    for (k,v) in m.headers.iter_mut(){if k=="cseq"{*v=format!("{} CANCEL",tx.cseq);}}
    serialize_request(&m,&tx.branch,cfg.advertised_ip,cfg.listen_port,false,None,Some(&tx.forwarded_uri))
}

async fn handle_invite(msg:SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{
    let callid=msg.header("call-id");let Some(cseq)=msg.cseq() else{return one_response(&msg,400,"Bad Request",source,state)};let key=(callid.clone(),cseq);
    if let Some(f)=state.forks.get(&key){
        if f.source!=source{return one_response(&msg,482,"Loop Detected",source,state);}
        let branches=f.branches.clone();let mut out=one_response(&msg,100,"Trying",source,state);
        for b in branches { if let Some(tx)=state.transactions.get(&b) { if !tx.final_seen&&!tx.forwarded_invite.is_empty(){out.push(Outbound{data:tx.forwarded_invite.clone(),target:tx.target});} } }
        return out;
    }
    if state.forks.len()>=MAX_ACTIVE_CALLS||state.transactions.len()>=MAX_TRANSACTIONS{return one_response(&msg,503,"Server Capacity Reached",source,state);}
    let caller=match validate_caller(cfg,&msg,source){Ok(Some(u))=>u,_=>return one_response(&msg,403,"Caller Not Registered",source,state)};
    let (callee,devices)=match choose_callee(cfg,&msg){Ok(Some(x))=>x,_=>{record_call(cfg,&msg,&caller,None,"not_found","Destination does not exist",404,source,None);return one_response(&msg,404,"Not Found",source,state)}};
    if devices.is_empty(){record_call(cfg,&msg,&caller,Some(&callee),"unavailable","No registered devices",480,source,None);return one_response(&msg,480,"Temporarily Unavailable",source,state);}
    if state.dialogs.values().any(|d|d.callee.eq_ignore_ascii_case(&callee.username)&&matches!(d.state.as_str(),"early"|"confirmed")){return one_response(&msg,486,"Busy Here",source,state);}
    let mut media_body=None;let mut new_relay=None;
    if !msg.body.is_empty()&&msg.header("content-type").to_ascii_lowercase().starts_with("application/sdp"){
        let offered=match parse_sdp_audio(&msg.body){Ok(a)=>a,Err(_)=>return one_response(&msg,488,"Not Acceptable Here",source,state)};
        let ips:Vec<IpAddr>=devices.iter().map(|d|d.ip).collect();
        match RtpRelayPair::new(cfg,source,offered,ips).await {Ok(relay)=>{match rewrite_sdp(&msg.body,relay.callee_rtp,relay.callee_rtcp,cfg.advertised_ip){Ok(body)=>media_body=Some(body),Err(e)=>{eprintln!("SDP rewrite failed: {e}");let mut r=relay;r.close();return one_response(&msg,488,"Not Acceptable Here",source,state);}}new_relay=Some(relay);},Err(e)=>{eprintln!("RTP allocation error: {e}");return one_response(&msg,488,"Not Acceptable Here",source,state)}}
    }
    let mut branch_list=Vec::new();let mut outbound=one_response(&msg,100,"Trying",source,state);
    let caller_uri=get_uri_user(&msg.header("from"));let _=caller_uri;
    let fork=Fork{call_id:callid.clone(),cseq,source,caller:caller.username.clone(),callee:callee.username.clone(),branches:Vec::new(),winner:None,finals:Vec::new(),cancelled:false,final_sent:false,original:msg.clone(),final_tx:None,expires:now_secs()+INVITE_RING_TIMEOUT_SECS};
    state.forks.insert(key.clone(),fork);
    state.dialogs.insert(callid.clone(),Dialog{caller:caller.username.clone(),callee:callee.username.clone(),caller_ep:source,callee_ep:None,state:"early".into(),expires:now_secs()+180});
    state.tags.insert(callid.clone(),random_hex(6));
    record_call(cfg,&msg,&caller,Some(&callee),"trying","INVITE forked to registered devices",100,source,devices.first().map(|d|SocketAddr::new(d.ip,d.port)));
    if let Some(r)=new_relay{state.relays.insert(callid.clone(),r);}
    let safe_user:String=callee.username.chars().filter(|c|c.is_ascii_alphanumeric()||".!%*_+`'~-".contains(*c)).collect();
    if safe_user.is_empty(){purge_call(state,&callid);return one_response(&msg,404,"Not Found",source,state);}
    for device in devices.iter().take(MAX_DEVICES_PER_ACCOUNT){
        let target=SocketAddr::new(device.ip,device.port);let branch=format!("z9hG4bK-pysip-{}",random_hex(12));let uri=dialog_uri(&safe_user,target);
        let packet=serialize_request(&msg,&branch,cfg.advertised_ip,cfg.listen_port,true,media_body.as_deref(),Some(&uri));let original_branch=branch_from_via(&msg);
        let tx=Transaction{branch:branch.clone(),original_branch,call_id:callid.clone(),cseq,method:"INVITE".into(),callee:callee.username.clone(),source,target,forwarded_uri:uri,forwarded_invite:packet.clone(),original:msg.clone(),final_seen:false,expires:now_secs()+TRANSACTION_TTL_SECS};
        state.transactions.insert(branch.clone(),tx);branch_list.push(branch);outbound.push(Outbound{data:packet,target});
    }
    if let Some(f)=state.forks.get_mut(&key){f.branches=branch_list;}
    outbound
}

fn handle_cancel(msg:SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{
    let callid=msg.header("call-id");let Some(cseq)=msg.cseq()else{return one_response(&msg,400,"Bad Request",source,state)};let key=(callid.clone(),cseq);
    let snapshot=state.forks.get(&key).map(|f|(f.source,f.winner.is_some(),f.branches.clone()));
    let Some((fork_source,has_winner,branches))=snapshot else{return one_response(&msg,481,"Call/Transaction Does Not Exist",source,state)};
    if fork_source!=source||has_winner{return one_response(&msg,481,"Call/Transaction Does Not Exist",source,state);}
    if let Some(f)=state.forks.get_mut(&key){f.cancelled=true;}
    let mut out=one_response(&msg,200,"OK",source,state);
    for b in branches{if let Some(tx)=state.transactions.get(&b){if !tx.final_seen{out.push(Outbound{data:make_cancel(tx,cfg),target:tx.target});}}}
    set_call_state(cfg,&callid,"cancelling","Caller cancelled pending INVITE",200);out
}

fn handle_ack(msg:SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{let callid=msg.header("call-id");let Some(cseq)=msg.cseq()else{return Vec::new()};let sender=get_uri_user(&msg.header("from"));let Some((user,_))=find_user(cfg,&sender,true).ok().flatten()else{return Vec::new()};if !registered_source(cfg,user.id,source){return Vec::new();}
    if let Some(f)=state.forks.get(&(callid.clone(),cseq)){if f.source==source&&f.winner.is_none(){if let Some(branch)=&f.final_tx{if let Some(tx)=state.transactions.get(branch){if branch_from_via(&msg)==tx.original_branch{return vec![Outbound{data:serialize_request(&msg,&tx.branch,cfg.advertised_ip,cfg.listen_port,false,None,Some(&tx.forwarded_uri)),target:tx.target}];}}}}}
    let Some((peer,target))=dialog_peer(state,&callid,&user.username,cfg)else{return Vec::new()};let uri=dialog_uri(&peer,target);let branch=format!("z9hG4bK-pysip-{}",random_hex(12));vec![Outbound{data:serialize_request(&msg,&branch,cfg.advertised_ip,cfg.listen_port,false,None,Some(&uri)),target}]
}
fn handle_dialog_request(msg:SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{let method=msg.method.clone();let callid=msg.header("call-id");let sender_name=get_uri_user(&msg.header("from"));let Some((sender,_))=find_user(cfg,&sender_name,true).ok().flatten()else{return one_response(&msg,403,"Sender Not Registered",source,state)};if !registered_source(cfg,sender.id,source){return one_response(&msg,403,"Sender Not Registered",source,state);}
    let peer=dialog_peer(state,&callid,&sender.username,cfg);
    let (target_name,target,uri)=if let Some((name,ep))=peer{let uri=dialog_uri(&name,ep);(name,ep,uri)}else if method=="MESSAGE"||method=="SUBSCRIBE"||method=="PUBLISH"{let dest=get_uri_user(&msg.uri);let Some((u,devices))=find_user(cfg,&dest,false).ok().flatten()else{return one_response(&msg,404,"Not Found",source,state)};let Some(d)=devices.first()else{return one_response(&msg,480,"Temporarily Unavailable",source,state)};let ep=SocketAddr::new(d.ip,d.port);(u.username.clone(),ep,dialog_uri(&u.username,ep))}else{return one_response(&msg,481,"Call/Transaction Does Not Exist",source,state)};
    let branch=format!("z9hG4bK-pysip-{}",random_hex(12));let Some(cseq)=msg.cseq()else{return one_response(&msg,400,"Bad Request",source,state)};let tx=Transaction{branch:branch.clone(),original_branch:branch_from_via(&msg),call_id:callid.clone(),cseq,method:method.clone(),callee:target_name.clone(),source,target,forwarded_uri:uri.clone(),forwarded_invite:Vec::new(),original:msg.clone(),final_seen:false,expires:now_secs()+TRANSACTION_TTL_SECS};state.transactions.insert(branch.clone(),tx);
    if method=="BYE"{set_call_state(cfg,&callid,"ending","BYE forwarded to dialog peer",0);println!("Call {callid}: BYE {} -> {} at {target}",sender.username,target_name);}
    vec![Outbound{data:serialize_request(&msg,&branch,cfg.advertised_ip,cfg.listen_port,false,None,Some(&uri)),target}]
}

async fn handle_response(msg:SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{
    let mut branch=branch_from_via(&msg);let mut fallback=false;let mut tx=state.transactions.get(&branch).cloned();
    if tx.is_none(){let cid=msg.header("call-id");let cseq=msg.cseq().unwrap_or(0);let mut candidates:Vec<Transaction>=state.transactions.values().filter(|t|t.call_id==cid&&t.cseq==cseq&&t.method==msg.method&&t.target.ip()==source.ip()).cloned().collect();if candidates.len()==1{tx=candidates.pop();fallback=true;}else if let Some(pos)=candidates.iter().position(|t|t.target==source){tx=Some(candidates.remove(pos));fallback=true;}if let Some(t)=&tx{branch=t.branch.clone();}}
    let Some(mut tx)=tx else{return Vec::new()};if source.ip()!=tx.target.ip(){return Vec::new();}
    if msg.method=="CANCEL"{return Vec::new();}
    let callid=tx.call_id.clone();let code=msg.status;println!("SIP {} response for {}: {} {}",msg.method,callid,code,msg.reason);
    if msg.method=="INVITE"{
        let key=(callid.clone(),tx.cseq);let Some(fork_snapshot)=state.forks.get(&key).map(|f|(f.source,f.branches.clone(),f.winner.clone(),f.final_sent,f.cancelled,f.callee.clone()))else{return Vec::new()};
        if fork_snapshot.3 {
            if (200..300).contains(&code){let out=late_fork_cleanup(&msg,&tx,source,cfg);return out;}
            if code>=300{if let Some(f)=state.forks.get(&key){if f.final_tx.as_deref()==Some(&branch){return vec![Outbound{data:serialize_response(&msg,cfg.advertised_ip,cfg.listen_port,None),target:f.source}];}}}return Vec::new();
        }
        if code<200 {if code>100{return vec![Outbound{data:serialize_response(&msg,cfg.advertised_ip,cfg.listen_port,None),target:fork_snapshot.0}];}return Vec::new();}
        if (200..300).contains(&code){
            let winner=state.forks.get(&key).and_then(|f|f.winner.clone());
            if winner.is_none(){if let Some(f)=state.forks.get_mut(&key){f.winner=Some(branch.clone());f.expires=now_secs()+86_400;}tx.final_seen=true;state.transactions.insert(branch.clone(),tx.clone());if let Some(d)=state.dialogs.get_mut(&callid){d.state="confirmed".into();d.callee_ep=Some(source);d.expires=now_secs()+86_400;}
                let mut body=msg.body.clone();if let Some(relay)=state.relays.get(&callid){if !body.is_empty()&&msg.header("content-type").to_ascii_lowercase().starts_with("application/sdp"){if let Ok(a)=parse_sdp_audio(&body){relay.set_callee_peer(source.ip(),a.rtp,a.rtcp).await;body=rewrite_sdp(&body,relay.caller_rtp,relay.caller_rtcp,cfg.advertised_ip).unwrap_or(body);}}}
                let mut out=vec![Outbound{data:serialize_response(&msg,cfg.advertised_ip,cfg.listen_port,Some(&body)),target:fork_snapshot.0}];set_call_state(cfg,&callid,"answered","Call answered; RTP relay active",code);
                for b in fork_snapshot.1 {if b!=branch{if let Some(other)=state.transactions.get(&b){if !other.final_seen{out.push(Outbound{data:make_cancel(other,cfg),target:other.target});}}}}
                println!("Call {callid} answered by {} at {source}",fork_snapshot.5);return out;
            } else if winner.as_deref()==Some(&branch){return vec![Outbound{data:serialize_response(&msg,cfg.advertised_ip,cfg.listen_port,None),target:fork_snapshot.0}];}
            tx.final_seen=true;state.transactions.insert(branch.clone(),tx.clone());return late_fork_cleanup(&msg,&tx,source,cfg);
        }
        if code>=300{
            tx.final_seen=true;state.transactions.insert(branch.clone(),tx.clone());
            if fork_snapshot.2.is_some(){ return Vec::new(); }
            if let Some(f)=state.forks.get_mut(&key){f.finals.push(FinalResponse{code,msg:msg.clone(),branch:branch.clone(),fallback});}
            let all_final=state.forks.get(&key).map(|f|f.branches.iter().all(|b|state.transactions.get(b).map(|t|t.final_seen).unwrap_or(true))).unwrap_or(false);
            if all_final {let f=state.forks.get_mut(&key).unwrap();let selected=f.finals.iter().find(|x|x.code==486||x.code==600).or_else(||f.finals.iter().find(|x|x.code==603)).or_else(||f.finals.first()).cloned();if let Some(sel)=selected{f.final_sent=true;f.final_tx=Some(sel.branch.clone());f.expires=now_secs()+TRANSACTION_TTL_SECS;let state_name=if sel.code==486||sel.code==600{"busy"}else if sel.code==603{"declined"}else if sel.code==487{"cancelled"}else{"failed"};set_call_state(cfg,&callid,state_name,&sel.msg.reason,sel.code);if let Some(mut r)=state.relays.remove(&callid){r.close();}state.dialogs.remove(&callid);return vec![Outbound{data:serialize_response(&sel.msg,cfg.advertised_ip,cfg.listen_port,None),target:f.source}];}}
        }
        return Vec::new();
    }
    let out=vec![Outbound{data:serialize_response(&msg,cfg.advertised_ip,cfg.listen_port,None),target:tx.source}];
    if tx.method=="BYE"&&code>=200&&code<300{set_call_state(cfg,&callid,"ended","Call ended normally",code);purge_call(state,&callid);}
    out
}
fn late_fork_cleanup(msg:&SipMessage,tx:&Transaction,source:SocketAddr,cfg:&Config)->Vec<Outbound>{let uri=dialog_uri(&tx.callee,source);let from=msg.header("from");let to=msg.header("to");let call=tx.call_id.clone();let seq=tx.cseq;let mut out=Vec::new();for (method,cseq) in [("ACK",seq),("BYE",seq+1)]{let b=format!("z9hG4bK-pysip-late-{}",random_hex(8));let packet=format!("{method} {uri} SIP/2.0\r\nVia: SIP/2.0/UDP {}:{};branch={b};rport\r\nFrom: {from}\r\nTo: {to}\r\nCall-ID: {call}\r\nCSeq: {cseq} {method}\r\nMax-Forwards: 69\r\nContent-Length: 0\r\n\r\n",cfg.advertised_ip,cfg.listen_port).into_bytes();out.push(Outbound{data:packet,target:source});}out}

fn dispatch(msg:SipMessage,source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{match msg.method.as_str(){"OPTIONS"=>{let mut v=one_response(&msg,200,"OK",source,state);let data=std::mem::take(&mut v[0].data);v[0].data=append_headers(data,&[format!("Allow: {}",SIP_METHODS.join(", ")),"Accept: application/sdp, text/plain".into()]);v},"CANCEL"=>handle_cancel(msg,source,cfg,state),"ACK"=>handle_ack(msg,source,cfg,state),"BYE"|"PRACK"|"UPDATE"|"INFO"|"REFER"|"MESSAGE"|"SUBSCRIBE"|"NOTIFY"|"PUBLISH"=>handle_dialog_request(msg,source,cfg,state),_=>one_response(&msg,501,"Not Implemented",source,state)}}

fn within_rate(state:&mut ServerState,ip:IpAddr)->bool{let now=Instant::now();let entry=state.rate.entry(ip).or_insert((now,0));if now.duration_since(entry.0)>=Duration::from_secs(1){*entry=(now,1);return true;}if entry.1>=120{return false;}entry.1+=1;true}
fn expire_state(cfg:&Config,state:&mut ServerState)->Vec<Outbound>{
    let now=now_secs();
    let keys:Vec<(String,u32)>=state.forks.iter().filter(|(_,f)|f.expires<=now&&!f.final_sent).map(|(k,_)|k.clone()).collect();
    let mut out=Vec::new();
    for key in keys {
        let snapshot=state.forks.get(&key).map(|f|(f.call_id.clone(),f.source,f.original.clone(),f.branches.clone(),f.cancelled,f.finals.clone()));
        let Some((callid,source,original,branches,cancelled,finals))=snapshot else{continue};
        for b in branches { if let Some(tx)=state.transactions.get(&b) { if !tx.final_seen { out.push(Outbound{data:make_cancel(tx,cfg),target:tx.target}); } } }
        let selected=if cancelled { finals.iter().find(|x|x.code==487).cloned() }
            else { finals.iter().find(|x|x.code==486||x.code==600).cloned()
                .or_else(||finals.iter().find(|x|x.code==603).cloned())
                .or_else(||finals.first().cloned()) };
        let selected_branch=selected.as_ref().map(|x|x.branch.clone());
        let (code,_reason,response_bytes,state_name,detail)=if let Some(sel)=selected.as_ref() {
            let name=if sel.code==486||sel.code==600{"busy"}else if sel.code==603{"declined"}else if sel.code==487{"cancelled"}else{"failed"};
            (sel.code,sel.msg.reason.clone(),serialize_response(&sel.msg,cfg.advertised_ip,cfg.listen_port,None),name,sel.msg.reason.clone())
        } else {
            let code=if cancelled{487}else{408};let reason=if code==487{"Request Terminated"}else{"Request Timeout"};
            (code,reason.to_string(),build_response(&original,code,reason,source,state),if code==487{"cancelled"}else{"unavailable"},reason.to_string())
        };
        out.push(Outbound{data:response_bytes,target:source});
        if let Some(f)=state.forks.get_mut(&key){f.final_sent=true;f.final_tx=selected_branch;f.expires=now+TRANSACTION_TTL_SECS;}
        set_call_state(cfg,&callid,state_name,&detail,code);
        if let Some(mut r)=state.relays.remove(&callid){r.close();}
        state.dialogs.remove(&callid);
    }
    let finished:Vec<String>=state.forks.values().filter(|f|f.final_sent&&f.expires<=now).map(|f|f.call_id.clone()).collect();
    for id in finished{purge_call(state,&id);}
    let active_dialogs:HashSet<String>=state.dialogs.keys().cloned().collect();
    state.transactions.retain(|_,t|t.expires>now||active_dialogs.contains(&t.call_id));
    let stale:Vec<String>=state.dialogs.iter().filter(|(_,d)|d.expires<=now).map(|(id,_)|id.clone()).collect();
    for id in stale{purge_call(state,&id);}
    if state.rate.len()>10_000{state.rate.clear();}
    if now%60==0 { if let Ok(c)=db_connect(cfg){let _=c.execute("DELETE FROM sip_contacts WHERE expires_at<=?1",[now as i64]);let _=c.execute("DELETE FROM registrations WHERE expires_at<=?1",[now as i64]);} }
    out
}

async fn handle_packet(data:&[u8],source:SocketAddr,cfg:&Config,state:&mut ServerState)->Vec<Outbound>{if data.iter().all(|b|*b==b'\r'||*b==b'\n'){return Vec::new();}if !within_rate(state,source.ip()){eprintln!("Rate limit: {source}");return Vec::new();}let msg=match parse_sip(data){Ok(Some(m))=>m,Ok(None)=>return Vec::new(),Err(e)=>{eprintln!("Dropped malformed SIP from {source}: {e}");return Vec::new();}};
    if !msg.is_response && msg.method!="ACK" { let mf=msg.header("max-forwards"); if !mf.is_empty() { match mf.parse::<u32>() { Ok(0)=>return one_response(&msg,483,"Too Many Hops",source,state), Err(_)=>return one_response(&msg,400,"Invalid Max-Forwards",source,state), _=>{} } } }
    if msg.is_response{return handle_response(msg,source,cfg,state).await;}
    if msg.method=="REGISTER"{return handle_register(&msg,source,cfg,state).await;}
    if msg.method=="INVITE"{return handle_invite(msg,source,cfg,state).await;}
    dispatch(msg,source,cfg,state)
}

fn detect_default_ip()->Option<IpAddr>{let s=std::net::UdpSocket::bind("0.0.0.0:0").ok()?;s.connect("1.1.1.1:53").ok()?;let ip=s.local_addr().ok()?.ip();if ip.is_loopback()||ip.is_unspecified(){None}else{Some(ip)}}
fn choose_advertised_ip()->IpAddr{if let Ok(v)=std::env::var("PYSIP_ADVERTISED_HOST"){let v=v.trim();if !v.is_empty()&&!matches!(v,"auto"|"select"|"localhost"|"127.0.0.1"|"0.0.0.0"){if let Ok(ip)=v.parse::<IpAddr>(){if ip.is_ipv4(){return ip;}}}}
    let mut addrs:Vec<(IpAddr,String)>=get_if_addrs().unwrap_or_default().into_iter().filter_map(|i|{let ip=i.ip();if ip.is_loopback()||ip.is_unspecified()||ip.is_multicast(){None}else if ip.is_ipv4(){Some((ip,i.name))}else{None}}).collect();addrs.sort_by_key(|(ip,_)|if Some(*ip)==detect_default_ip(){0}else{1});addrs.dedup_by_key(|(ip,_)|*ip);if addrs.is_empty(){return IpAddr::V4(Ipv4Addr::LOCALHOST);}if !io::stdin().is_terminal(){return detect_default_ip().unwrap_or(addrs[0].0);}println!("\nAvailable IPv4 addresses:");for (i,(ip,name)) in addrs.iter().enumerate(){println!("  [{}] {:<16} ({})",i+1,ip,name);}println!("  [0] Auto-detect / default route");print!("Select advertised IP [1]: ");let _=io::stdout().flush();let mut input=String::new();let _=io::stdin().read_line(&mut input);match input.trim().parse::<usize>(){Ok(0)=>detect_default_ip().unwrap_or(addrs[0].0),Ok(n) if n<=addrs.len()=>addrs[n-1].0,_=>addrs[0].0}}
fn load_config()->Config{let db=std::env::var("PYSIP_DB_PATH").unwrap_or_else(|_|DEFAULT_DB.into());let realm=std::env::var("PYSIP_REALM").unwrap_or_else(|_|DEFAULT_REALM.into());let listen_ip=std::env::var("PYSIP_HOST").ok().and_then(|v|v.parse().ok()).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));let listen_port=std::env::var("PYSIP_PORT").ok().and_then(|v|v.parse().ok()).unwrap_or(SIP_PORT);let rtp_min=std::env::var("PYSIP_RTP_PORT_MIN").ok().and_then(|v|v.parse().ok()).unwrap_or(RTP_MIN_DEFAULT);let rtp_max=std::env::var("PYSIP_RTP_PORT_MAX").ok().and_then(|v|v.parse().ok()).unwrap_or(RTP_MAX_DEFAULT);Config{db_path:PathBuf::from(db),realm,listen_ip,listen_port,advertised_ip:choose_advertised_ip(),rtp_min,rtp_max}}

#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    let cfg=load_config();ensure_schema(&cfg)?;persist_advertised_host(&cfg)?;
    let bind=SocketAddr::new(cfg.listen_ip,cfg.listen_port);let socket=UdpSocket::bind(bind).await?;let socket=Arc::new(socket);let mut state=ServerState::new();let mut buf=vec![0u8;MAX_PACKET+1];let mut tick=interval(Duration::from_secs(1));
    println!("\n========================================\n  PySIP Rust SIP Server 1.0\n========================================\nListening:     {bind}/UDP\nAdvertised IP: {}\nRTP/RTCP:      UDP {}-{}\nDatabase:      {}\n",cfg.advertised_ip,cfg.rtp_min,cfg.rtp_max,cfg.db_path.display());
    loop{tokio::select!{
        received=socket.recv_from(&mut buf)=>{let (n,source)=received?;if n>MAX_PACKET{continue;}let out=handle_packet(&buf[..n],source,&cfg,&mut state).await;for item in out{let _=socket.send_to(&item.data,item.target).await;}},
        _=tick.tick()=>{let out=expire_state(&cfg,&mut state);for item in out{let _=socket.send_to(&item.data,item.target).await;}},
        _=tokio::signal::ctrl_c()=>{break;}
    }}
    for (_,mut relay) in state.relays.drain(){relay.close();}
    println!("PySIP stopped.");Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn parses_register_and_compact_headers(){let raw=b"REGISTER sip:tester@pysip.local SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-x;rport\r\nFrom: <sip:tester@pysip.local>;tag=a\r\nTo: <sip:tester@pysip.local>\r\nCall-ID: abc\r\nCSeq: 1 REGISTER\r\nContact: <sip:tester@127.0.0.1:5060>\r\nContent-Length: 0\r\n\r\n";let m=parse_sip(raw).unwrap().unwrap();assert_eq!(m.method,"REGISTER");assert_eq!(m.header("call-id"),"abc");}
    #[test] fn ignores_crlf_keepalive(){assert!(parse_sip(b"\r\n\r\n").unwrap().is_none());}
    #[test] fn resolves_username_and_phone_userpart(){assert_eq!(get_uri_user("<sip:+1901234567@pysip.local>"),"+1901234567");}
    #[test] fn splits_contacts_without_breaking_name_addr(){let v=split_header_values("\"Desk, PC\" <sip:a@host>;expires=60, <sip:b@host>;expires=120");assert_eq!(v.len(),2);}
    #[test] fn sdp_rewrite_preserves_audio_codec(){let s=b"v=0\r\no=- 1 1 IN IP4 192.168.0.2\r\ns=-\r\nc=IN IP4 192.168.0.2\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n";let r=rewrite_sdp(s,25000,25001,"192.168.0.3".parse().unwrap()).unwrap();let t=String::from_utf8(r).unwrap();assert!(t.contains("m=audio 25000 RTP/AVP 0 8"));assert!(t.contains("a=rtcp:25001 IN IP4 192.168.0.3"));assert!(t.contains("a=rtpmap:0 PCMU/8000"));assert_eq!(t.matches("c=IN IP4 192.168.0.3").count(),1);}
    #[test] fn digest_parser_handles_quoted_commas(){let h=parse_digest("Digest username=\"pc,desk\", realm=\"pysip.local\", qop=auth, nc=00000001");assert_eq!(h.get("username").unwrap(),"pc,desk");}
    #[test] fn phone_resolution_normalizes_digits(){assert_eq!(normalize_phone("1901234567"),"+1901234567");assert_eq!(normalize_phone("+190-123-4567"),"+1901234567");}
    #[test] fn digest_ha1_matches_legacy_python_format(){assert_eq!(md5_hex("tester2:pysip.local:ExamplePass123!"),"f2252b5d5aabb105b1220a5a59656c87");}
    #[test] fn existing_web_database_schema_and_multi_contact_lookup(){
        let path=std::env::temp_dir().join(format!("pysip-rust-test-{}.db",random_hex(6)));
        let cfg=Config{db_path:path.clone(),realm:DEFAULT_REALM.into(),listen_ip:IpAddr::V4(Ipv4Addr::UNSPECIFIED),listen_port:5060,advertised_ip:IpAddr::V4(Ipv4Addr::LOCALHOST),rtp_min:20000,rtp_max:30000};
        ensure_schema(&cfg).unwrap();
        { let c=db_connect(&cfg).unwrap();
          c.execute("INSERT INTO users(username,password_hash,sip_ha1,phone_number,enabled,created_at) VALUES('tester2','pbkdf2$test','deadbeef','+19012345678',1,?1)",[now_secs() as i64]).unwrap();
          c.execute("INSERT INTO sip_contacts(user_id,contact_uri,source_ip,source_port,user_agent,expires_at,call_id,cseq,updated_at) VALUES(1,'sip:pc@192.168.1.10','192.168.1.10',5062,'PC',?1,'pc-call',1,?2)",params![now_secs() as i64+600,now_secs() as i64]).unwrap();
          c.execute("INSERT INTO sip_contacts(user_id,contact_uri,source_ip,source_port,user_agent,expires_at,call_id,cseq,updated_at) VALUES(1,'sip:phone@192.168.1.11','192.168.1.11',5064,'Phone',?1,'phone-call',1,?2)",params![now_secs() as i64+600,now_secs() as i64]).unwrap(); }
        let found=find_user(&cfg,"+19012345678",true).unwrap().unwrap();
        assert_eq!(found.0.username,"tester2");assert_eq!(found.1.len(),2);
        assert!(source_registered(&cfg,found.0.id,"192.168.1.11:5064".parse().unwrap()).unwrap());
        let _=std::fs::remove_file(path);
    }
}
