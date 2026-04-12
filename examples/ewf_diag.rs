// Diagnostic: find the ewf chunk containing a given logical offset
// and dump its metadata + surrounding E01 bytes.
//
// Run: cargo run --release --example ewf_diag -- <E01_PATH> <HEX_OFFSET>

use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: ewf_diag <E01_PATH> <HEX_LOGICAL_OFFSET>");
        std::process::exit(1);
    }

    let path = &args[1];
    let target_off = {
        let s = args[2].trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).expect("bad hex offset")
    };

    println!("[i] Opening: {}", path);
    println!("[i] Target logical offset: {:#x} ({:.2} GB)", target_off, target_off as f64 / 1_073_741_824.0);

    let reader = ewf::EwfReader::open(path).expect("open E01");
    let total = reader.total_size();
    let chunk_size = reader.chunk_size();
    println!("[i] Logical disk size: {} bytes ({:.2} GB)", total, total as f64 / 1_073_741_824.0);
    println!("[i] Logical chunk size: {} bytes ({} KB)", chunk_size, chunk_size / 1024);

    // Reflect into internal chunk table via the public API we have.
    // The ewf crate doesn't expose chunks directly, so we scan via the chunks() iterator
    // if it exists, otherwise fall back to sequential probing.

    // Work around: we know logical offset / chunk_size = chunk index
    let target_chunk_idx = target_off / chunk_size;
    println!("[i] Target chunk index: {} (chunk {} of ~{})", target_chunk_idx, target_chunk_idx, total / chunk_size);

    // Try to dump the chunk table around target: we don't have access to internals,
    // so let's instead time small reads around the zone.
    let mut reader = reader;
    let probe_start = target_chunk_idx * chunk_size;
    let probe_end = probe_start + 4 * 1024 * 1024; // 4 MB window == 128 chunks

    // NEW: simulate masstin — sequential 4 MB reads from (target - 100 MB) forward,
    // same reader, no reopen. Find the actual stall.
    println!("\n[i] Simulating masstin sequential 4 MB reads starting from {:#x} - 100 MB:", target_off);
    {
        let mut r = ewf::EwfReader::open(path).unwrap();
        let start = target_off.saturating_sub(100 * 1024 * 1024);
        let end = (target_off + 200 * 1024 * 1024).min(total);
        let _ = r.seek(SeekFrom::Start(start));
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut cur = start;
        let mut count = 0;
        while cur < end {
            let t = std::time::Instant::now();
            match r.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let el = t.elapsed();
                    if el.as_millis() > 500 || count % 10 == 0 {
                        println!("  [seq] off={:#x} read {} bytes in {:?}", cur, n, el);
                    }
                    if el.as_secs() > 3 {
                        println!("  *** SLOW READ at {:#x} — {:?} ***", cur, el);
                    }
                    cur += n as u64;
                    count += 1;
                }
                Ok(_) => break,
                Err(e) => { println!("  [seq] off={:#x} ERR: {}", cur, e); break; }
            }
        }
        println!("  [seq] completed {} reads from {:#x} to {:#x}", count, start, cur);
    }

    // First: try a 4 MB read from the target offset (what masstin actually does)
    println!("\n[i] Testing 4 MB read from {:#x} (isolated, new reader):", target_off);
    {
        let path_clone = path.clone();
        let target = target_off;
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut r = ewf::EwfReader::open(&path_clone).unwrap();
            let _ = r.seek(SeekFrom::Start(target));
            let mut big_buf = vec![0u8; 4 * 1024 * 1024];
            let t = std::time::Instant::now();
            let result = r.read(&mut big_buf);
            let _ = tx.send((result, t.elapsed()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok((Ok(n), elapsed)) => {
                println!("  4 MB read OK: {} bytes in {:?}", n, elapsed);
            }
            Ok((Err(e), elapsed)) => {
                println!("  4 MB read ERR after {:?}: {}", elapsed, e);
            }
            Err(_) => {
                println!("  *** 4 MB read STALLED (>30s) — reproduced the masstin hang! ***");
                std::mem::forget(handle);
            }
        }
    }

    // Now: bisect the 4 MB range in 32 KB reads to find which individual chunk stalls
    println!("\n[i] Bisecting 4 MB range in 32 KB reads to find the bad chunk:");

    for logical in (probe_start..probe_end).step_by(chunk_size as usize) {
        let idx = logical / chunk_size;
        let start = std::time::Instant::now();
        let _ = reader.seek(SeekFrom::Start(logical));
        let mut buf = vec![0u8; chunk_size as usize];
        // Use a thread to bound the wait
        let (tx, rx) = std::sync::mpsc::channel();
        let path_clone = path.clone();
        let handle = std::thread::spawn(move || {
            let mut r = match ewf::EwfReader::open(&path_clone) {
                Ok(r) => r,
                Err(e) => { let _ = tx.send(Err(format!("open: {}", e))); return; }
            };
            let _ = r.seek(SeekFrom::Start(logical));
            match r.read(&mut buf) {
                Ok(n) => { let _ = tx.send(Ok((n, buf))); }
                Err(e) => { let _ = tx.send(Err(format!("read: {}", e))); }
            }
        });

        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok((n, data))) => {
                let elapsed = start.elapsed();
                let first8: Vec<String> = data.iter().take(16).map(|b| format!("{:02x}", b)).collect();
                println!("  chunk {:>6} @ {:#012x}: OK  {} bytes in {:?} | first16: {}",
                    idx, logical, n, elapsed, first8.join(" "));
                let _ = handle.join();
            }
            Ok(Err(e)) => {
                println!("  chunk {:>6} @ {:#012x}: ERR {}", idx, logical, e);
                let _ = handle.join();
            }
            Err(_) => {
                println!("  chunk {:>6} @ {:#012x}: *** STALL (>5s) ***  <-- bad chunk!", idx, logical);
                std::mem::forget(handle);
                // Skip past this chunk
            }
        }
    }

    // Now dump raw E01 bytes from the underlying file to see the actual structure
    println!("\n[i] Raw E01 file inspection:");
    let mut f = File::open(path).expect("open raw");
    let e01_size = f.metadata().unwrap().len();
    println!("[i] E01 file size: {} bytes ({:.2} GB)", e01_size, e01_size as f64 / 1_073_741_824.0);

    // Scan for "table" and "table2" section signatures around the middle of file
    // EWF sections: 16-byte descriptor with ASCII type at start
    println!("\n[i] Scanning for EWF section headers in raw E01 (first 100 matches):");
    let mut pos: u64 = 0;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut matches = 0;
    while pos < e01_size && matches < 100 {
        let _ = f.seek(SeekFrom::Start(pos));
        let n = match f.read(&mut buf) { Ok(n) if n > 0 => n, _ => break };
        let mut i = 0;
        while i + 16 <= n {
            let tag = &buf[i..i+16];
            // Section descriptor starts with ASCII section type (up to 16 bytes, padded with 0)
            // Known types: header, header2, volume, disk, sectors, table, table2, data, digest, hash, error2, session, done, next
            let first = tag[0];
            if first.is_ascii_lowercase() {
                let end = tag.iter().position(|&b| b == 0).unwrap_or(16);
                let name = std::str::from_utf8(&tag[..end]).unwrap_or("");
                if matches!(name, "header" | "header2" | "volume" | "disk" | "sectors" | "table" | "table2" | "data" | "digest" | "hash" | "error2" | "session" | "done" | "next") {
                    println!("  {:#014x}: section '{}' ", pos + i as u64, name);
                    matches += 1;
                    if matches >= 100 { break; }
                }
            }
            i += 1;
        }
        pos += n as u64;
        if n < buf.len() { break; }
    }
}
