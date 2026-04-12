// Scans a logical range of an E01 for ElfChnk signatures and tries to parse
// each with a 5s timeout, reporting which chunk makes the evtx crate hang.
//
// Run: cargo run --release --example evtx_parse_diag -- <E01> <HEX_START> <HEX_END>

use std::env;
use std::io::{Read, Seek, SeekFrom};
use std::sync::mpsc;
use std::time::Duration;

const ELFCHNK: &[u8; 8] = b"ElfChnk\x00";
const CHUNK_SIZE: usize = 65536;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: evtx_parse_diag <E01> <HEX_START> <HEX_END>");
        std::process::exit(1);
    }
    let path = args[1].clone();
    let parse_hex = |s: &str| -> u64 {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).unwrap()
    };
    let start = parse_hex(&args[2]);
    let end = parse_hex(&args[3]);

    println!("[i] Scanning {:#x}..{:#x} ({:.1} MB)", start, end, (end - start) as f64 / 1048576.0);

    let mut r = ewf::EwfReader::open(&path).expect("open");
    let _ = r.seek(SeekFrom::Start(start));

    let block_size = 4 * 1024 * 1024;
    let mut buf = vec![0u8; block_size];
    let mut cur = start;
    let mut found = 0;

    while cur < end {
        let to_read = block_size.min((end - cur) as usize);
        let n = match r.read(&mut buf[..to_read]) {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        // Scan for ElfChnk
        let mut pos = 0;
        while pos + CHUNK_SIZE <= n {
            if &buf[pos..pos + 8] == ELFCHNK {
                found += 1;
                let abs = cur + pos as u64;
                let chunk = buf[pos..pos + CHUNK_SIZE].to_vec();
                println!("\n[{}] ElfChnk at {:#x}", found, abs);
                println!("  first 32 bytes: {:02x?}", &chunk[..32]);

                // Try to parse with 5s timeout
                let (tx, rx) = mpsc::channel();
                let chunk_clone = chunk.clone();
                let t = std::time::Instant::now();
                let handle = std::thread::spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut cd = evtx::EvtxChunkData::new(chunk_clone, false).ok()?;
                        let settings = std::sync::Arc::new(evtx::ParserSettings::default());
                        let mut parsed = cd.parse(settings).ok()?;
                        for rec in parsed.iter() {
                            if let Ok(record) = rec {
                                let mut xml_buf: Vec<u8> = Vec::new();
                                let mut out = evtx::XmlOutput::with_writer(&mut xml_buf, &evtx::ParserSettings::default());
                                let _ = record.into_output(&mut out);
                                let xml = String::from_utf8_lossy(&out.into_writer()).to_string();
                                if let Some(s) = xml.find("Provider Name=\"") {
                                    let after = &xml[s + 15..];
                                    if let Some(e) = after.find('"') {
                                        return Some(after[..e].to_string());
                                    }
                                }
                            }
                            break;
                        }
                        Some("Unknown".to_string())
                    }));
                    let _ = tx.send(result);
                });

                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(Ok(Some(provider))) => {
                        println!("  parse OK in {:?}: provider={}", t.elapsed(), provider);
                        let _ = handle.join();
                    }
                    Ok(Ok(None)) => {
                        println!("  parse returned None in {:?} (invalid chunk)", t.elapsed());
                        let _ = handle.join();
                    }
                    Ok(Err(_)) => {
                        println!("  parse PANICKED in {:?}", t.elapsed());
                        let _ = handle.join();
                    }
                    Err(_) => {
                        println!("  *** PARSE HUNG >5s — THIS IS THE BUG *** at {:#x}", abs);
                        // Dump the chunk to a file for analysis
                        let dump_path = format!("bad_chunk_{:x}.bin", abs);
                        std::fs::write(&dump_path, &chunk).unwrap();
                        println!("  dumped to {}", dump_path);
                        std::mem::forget(handle);
                    }
                }
                pos += CHUNK_SIZE;
            } else {
                pos += 512;
            }
        }
        cur += n as u64;
    }
    println!("\n[i] Total ElfChnk signatures found: {}", found);
}
