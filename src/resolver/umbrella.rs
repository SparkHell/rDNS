use super::normalize_domain;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, Cursor, Read},
};

pub(super) const URL: &str = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip";
pub(super) const SNAPSHOT_VERSION: u8 = 1;
const CSV_LIMIT: u64 = 96 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Snapshot {
    #[serde(default)]
    pub version: u8,
    pub hosts: HashMap<String, Vec<String>>,
    pub updated_at: i64,
    pub attempted_at: i64,
    pub error: Option<String>,
}

pub(super) fn extract(
    bytes: Vec<u8>,
    parents: HashSet<String>,
) -> Result<HashMap<String, Vec<String>>> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
    let csv = zip.by_name("top-1m.csv")?;
    ensure!(csv.size() <= CSV_LIMIT, "Umbrella CSV too large");
    let mut reader = BufReader::new(csv.take(CSV_LIMIT + 1));
    let mut matched: HashMap<_, _> = parents.into_iter().map(|p| (p, Vec::new())).collect();
    let mut seen = HashSet::new();
    let mut line = String::new();
    let mut bytes_read = 0;
    let mut last = 0;
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        bytes_read += n;
        ensure!(
            bytes_read <= CSV_LIMIT as usize,
            "Umbrella CSV exceeds limit"
        );
        let (rank, host) = line
            .trim_end()
            .split_once(',')
            .ok_or_else(|| anyhow::anyhow!("invalid Umbrella CSV"))?;
        let rank: u32 = rank.parse()?;
        ensure!(rank == last + 1, "unexpected Umbrella rank");
        last = rank;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut suffix = host.as_str();
        let mut validated = false;
        while let Some((_, parent)) = suffix.split_once('.') {
            if let Some(names) = matched.get_mut(parent) {
                if !validated {
                    if normalize_domain(&host).is_err() || !seen.insert(host.clone()) {
                        break;
                    }
                    validated = true;
                }
                names.push(host.clone());
            }
            suffix = parent;
        }
    }
    ensure!(last == 1_000_000, "incomplete Umbrella Top 1M");
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn partial_archive_is_rejected() -> Result<()> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("top-1m.csv", zip::write::SimpleFileOptions::default())?;
        zip.write_all(b"1,cdn.example.com\n2,example.com\n")?;
        let bytes = zip.finish()?.into_inner();
        assert!(extract(bytes, HashSet::from(["example.com".into()])).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires an official Cisco Top 1M ZIP at RDNS_UMBRELLA_ZIP"]
    fn official_archive_matches_ranked_hosts() -> Result<()> {
        let bytes = std::fs::read(std::env::var("RDNS_UMBRELLA_ZIP")?)?;
        let parents = HashSet::from(["bilivideo.com".to_owned(), "qq.com".to_owned()]);
        let names = extract(bytes, parents)?;
        for (parent, hosts) in names {
            assert!(hosts.len() > 8, "{parent} still looks truncated");
            assert!(hosts.iter().all(|h| h.ends_with(&format!(".{parent}"))));
            println!("{parent}: {} subdomains", hosts.len());
        }
        Ok(())
    }
}
