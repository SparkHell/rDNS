//! Offline ip2region XDB v3 lookup, adapted from MirrorProxy.
//!
//! The XDB lookup algorithm is adapted from the official ip2region Rust
//! binding (https://github.com/lionsoul2014/ip2region), licensed under
//! Apache-2.0 OR MIT. Keeping the small reader here avoids pulling the XDB
//! maker CLI and its build-only dependencies into the server binary.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::UNIX_EPOCH,
};

use anyhow::{Context, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

const HEADER_LENGTH: usize = 256;
const VECTOR_INDEX_LENGTH: usize = 256 * 256 * 8;
const MAX_XDB_BYTES: usize = 80 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub country_code: Option<String>,
}

impl GeoLocation {
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn from_xdb(value: &str) -> Self {
        let mut fields = value.split('|').map(normalize_field);
        Self {
            country: fields.next().flatten(),
            province: fields.next().flatten(),
            city: fields.next().flatten(),
            isp: fields.next().flatten(),
            country_code: fields.next().flatten().map(|value| value.to_uppercase()),
        }
    }
}

fn normalize_field(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("reserved"))
        .then(|| value.to_string())
}

#[derive(Clone, Debug, Serialize)]
pub struct GeoDatabaseStatus {
    pub ip_version: u8,
    pub available: bool,
    pub path: String,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeoIpStatus {
    pub enabled: bool,
    pub ipv4: GeoDatabaseStatus,
    pub ipv6: GeoDatabaseStatus,
}

#[derive(Clone)]
pub struct GeoIpService {
    enabled: bool,
    ipv4_path: PathBuf,
    ipv6_path: PathBuf,
    readers: Arc<RwLock<Readers>>,
}

#[derive(Default)]
struct Readers {
    ipv4: Option<Arc<XdbReader>>,
    ipv6: Option<Arc<XdbReader>>,
    ipv4_error: Option<String>,
    ipv6_error: Option<String>,
}

impl GeoIpService {
    pub fn new(enabled: bool, ipv4_path: PathBuf, ipv6_path: PathBuf) -> Self {
        let service = Self {
            enabled,
            ipv4_path,
            ipv6_path,
            readers: Arc::new(RwLock::new(Readers::default())),
        };
        service.reload();
        service
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoLocation {
        if !self.enabled || !is_public_ip(ip) {
            return GeoLocation::unknown();
        }
        let readers = self.readers.read().expect("GeoIP reader lock poisoned");
        let reader = match ip {
            IpAddr::V4(_) => readers.ipv4.as_ref(),
            IpAddr::V6(_) => readers.ipv6.as_ref(),
        };
        reader
            .and_then(|reader| reader.lookup(ip).ok().flatten())
            .map(|value| GeoLocation::from_xdb(&value))
            .unwrap_or_default()
    }

    pub fn status(&self) -> GeoIpStatus {
        let readers = self.readers.read().expect("GeoIP reader lock poisoned");
        GeoIpStatus {
            enabled: self.enabled,
            ipv4: database_status(
                4,
                &self.ipv4_path,
                readers.ipv4.as_deref(),
                readers.ipv4_error.clone(),
            ),
            ipv6: database_status(
                6,
                &self.ipv6_path,
                readers.ipv6.as_deref(),
                readers.ipv6_error.clone(),
            ),
        }
    }

    pub fn database_path(&self, version: u8) -> anyhow::Result<&Path> {
        match version {
            4 => Ok(&self.ipv4_path),
            6 => Ok(&self.ipv6_path),
            _ => bail!("ip_version must be 4 or 6"),
        }
    }

    pub fn install_database(&self, version: u8, data: &[u8]) -> anyhow::Result<()> {
        if data.len() > MAX_XDB_BYTES {
            bail!("XDB database exceeds the 80 MiB safety limit");
        }
        let expected_version = match version {
            4 => XdbIpVersion::V4,
            6 => XdbIpVersion::V6,
            _ => bail!("ip_version must be 4 or 6"),
        };
        let reader = XdbReader::from_bytes(data.to_vec())?;
        if reader.ip_version != expected_version {
            bail!("XDB IP version does not match the requested database");
        }
        let probe = if version == 4 {
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        } else {
            "2606:4700:4700::1111".parse().expect("valid IPv6 probe")
        };
        let _ = reader.lookup(probe)?;

        let path = self.database_path(version)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let temporary = path.with_extension("xdb.tmp");
        let backup = path.with_extension("xdb.bak");
        fs::write(&temporary, data)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        if path.exists() {
            let _ = fs::copy(path, &backup);
        }
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        self.reload();
        Ok(())
    }

    fn reload(&self) {
        let (ipv4, ipv4_error) = load_reader(&self.ipv4_path, XdbIpVersion::V4);
        let (ipv6, ipv6_error) = load_reader(&self.ipv6_path, XdbIpVersion::V6);
        let mut readers = self.readers.write().expect("GeoIP reader lock poisoned");
        readers.ipv4 = ipv4.map(Arc::new);
        readers.ipv6 = ipv6.map(Arc::new);
        readers.ipv4_error = ipv4_error;
        readers.ipv6_error = ipv6_error;
    }
}

fn load_reader(path: &Path, expected: XdbIpVersion) -> (Option<XdbReader>, Option<String>) {
    match XdbReader::open(path) {
        Ok(reader) if reader.ip_version == expected => (Some(reader), None),
        Ok(_) => (None, Some("XDB IP version mismatch".to_string())),
        Err(error) => (None, Some(error.to_string())),
    }
}

fn database_status(
    version: u8,
    path: &Path,
    reader: Option<&XdbReader>,
    error: Option<String>,
) -> GeoDatabaseStatus {
    let metadata = fs::metadata(path).ok();
    GeoDatabaseStatus {
        ip_version: version,
        available: reader.is_some(),
        path: path.display().to_string(),
        created_at: reader.map(|reader| u64::from(reader.created_at)),
        modified_at: metadata
            .as_ref()
            .and_then(|value| value.modified().ok())
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs()),
        size_bytes: metadata.map(|value| value.len()),
        sha256: reader.map(|reader| reader.sha256.clone()),
        error: reader
            .is_none()
            .then(|| error.unwrap_or_else(|| "database unavailable".into())),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XdbIpVersion {
    V4,
    V6,
}

struct XdbReader {
    bytes: Arc<Vec<u8>>,
    ip_version: XdbIpVersion,
    created_at: u32,
    sha256: String,
}

impl XdbReader {
    fn open(path: &Path) -> anyhow::Result<Self> {
        if fs::metadata(path)
            .with_context(|| format!("failed to inspect {}", path.display()))?
            .len()
            > MAX_XDB_BYTES as u64
        {
            bail!("XDB database exceeds the 80 MiB size limit");
        }
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_bytes(bytes)
    }

    fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        if bytes.len() < HEADER_LENGTH + VECTOR_INDEX_LENGTH {
            bail!("XDB file is truncated");
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version != 3 {
            bail!("unsupported XDB version {version}; expected version 3");
        }
        let index_policy = u16::from_le_bytes([bytes[2], bytes[3]]);
        if index_policy != 1 {
            bail!("unsupported XDB index policy {index_policy}");
        }
        let created_at = u32::from_le_bytes(bytes[4..8].try_into()?);
        let ip_version = match u16::from_le_bytes([bytes[16], bytes[17]]) {
            4 => XdbIpVersion::V4,
            6 => XdbIpVersion::V6,
            value => bail!("unsupported XDB IP version {value}"),
        };
        if u16::from_le_bytes([bytes[18], bytes[19]]) != 4 {
            bail!("unsupported XDB pointer width");
        }
        let first = read_u32(&bytes, 8)? as usize;
        let last = read_u32(&bytes, 12)? as usize;
        let record_length = if ip_version == XdbIpVersion::V4 {
            14
        } else {
            38
        };
        if first < HEADER_LENGTH + VECTOR_INDEX_LENGTH
            || last < first
            || !(last - first).is_multiple_of(record_length)
            || last
                .checked_add(record_length)
                .is_none_or(|end| end > bytes.len())
        {
            bail!("invalid XDB segment index bounds");
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(Self {
            bytes: Arc::new(bytes),
            ip_version,
            created_at,
            sha256,
        })
    }

    fn lookup(&self, ip: IpAddr) -> anyhow::Result<Option<String>> {
        let octets: Vec<u8> = match (ip, self.ip_version) {
            (IpAddr::V4(ip), XdbIpVersion::V4) => ip.octets().to_vec(),
            (IpAddr::V6(ip), XdbIpVersion::V6) => ip.octets().to_vec(),
            _ => bail!("IP version does not match XDB database"),
        };
        let point = HEADER_LENGTH + ((usize::from(octets[0]) * 256 + usize::from(octets[1])) * 8);
        let start = read_u32(&self.bytes, point)? as usize;
        let end = read_u32(&self.bytes, point + 4)? as usize;
        if start == 0 || end == 0 || end < start {
            return Ok(None);
        }
        let ip_len = octets.len();
        let record_len = ip_len * 2 + 6;
        let mut left = 0usize;
        let mut right = (end - start) / record_len;
        while left <= right {
            let mid = (left + right) / 2;
            let offset = start.saturating_add(mid.saturating_mul(record_len));
            let record = slice(&self.bytes, offset, record_len)?;
            let start_ip = decode_index_ip(&record[..ip_len], self.ip_version);
            let end_ip = decode_index_ip(&record[ip_len..ip_len * 2], self.ip_version);
            if octets < start_ip {
                let Some(next) = mid.checked_sub(1) else {
                    break;
                };
                right = next;
            } else if octets > end_ip {
                left = mid + 1;
            } else {
                let length =
                    u16::from_le_bytes(record[ip_len * 2..ip_len * 2 + 2].try_into()?) as usize;
                let data_offset =
                    u32::from_le_bytes(record[ip_len * 2 + 2..ip_len * 2 + 6].try_into()?) as usize;
                return Ok(Some(String::from_utf8(
                    slice(&self.bytes, data_offset, length)?.to_vec(),
                )?));
            }
        }
        Ok(None)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    Ok(u32::from_le_bytes(slice(bytes, offset, 4)?.try_into()?))
}

fn slice(bytes: &[u8], offset: usize, length: usize) -> anyhow::Result<&[u8]> {
    bytes
        .get(offset..offset.saturating_add(length))
        .context("XDB pointer is outside the database")
}

fn decode_index_ip(bytes: &[u8], version: XdbIpVersion) -> Vec<u8> {
    match version {
        XdbIpVersion::V4 => bytes.iter().rev().copied().collect(),
        XdbIpVersion::V6 => bytes.to_vec(),
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.segments()[0] & 0xfe00 == 0xfc00
                || ip.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}
