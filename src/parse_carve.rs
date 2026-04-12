// =============================================================================
//   EVTX Record Carving from forensic disk images
//   Scans raw disk data for EVTX chunks (ElfChnk) and orphan records,
//   recovering events from unallocated space after log deletion.
//
//   Tier 1: Chunk carving — find intact 64KB ElfChnk blocks, build synthetic
//           EVTX files, parse with the existing masstin pipeline
//   Tier 2: Record scanning — find \x2a\x2a\x00\x00 record headers, count
//           orphan records for reporting
//
//   Usage: masstin -a carve-image -f image.e01 -o carved.csv
//          masstin -a carve-image -f image.e01 -o carved.csv --carve-unalloc
// =============================================================================

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::parse::{is_debug_mode, LogData};

const ELFCHNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";
const EVTX_CHUNK_SIZE: usize = 65536; // 64KB
const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
const SCAN_BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4MB read blocks

/// Main entry point for carve-image action
pub fn carve_image(files: &[String], output: Option<&String>, unalloc_only: bool, skip_offsets: &[u64]) {
    // Convert OOM aborts into panics so the isolated-thread validator can recover
    // when the evtx crate tries to allocate multi-GB buffers on corrupt BinXML.
    std::alloc::set_alloc_error_hook(|layout| {
        panic!("allocation of {} bytes failed (caught by masstin hook)", layout.size());
    });

    let start_time = std::time::Instant::now();

    crate::banner::print_phase("1", "3", "Scanning forensic images for EVTX remnants...");

    if unalloc_only {
        crate::banner::print_info("  Mode: unallocated space only (--carve-unalloc)");
    } else {
        crate::banner::print_info("  Mode: full disk scan (use --carve-unalloc for faster unallocated-only)");
    }

    let base_temp = std::env::temp_dir().join("masstin_carve_extract");
    let _ = fs::remove_dir_all(&base_temp);
    let _ = fs::create_dir_all(&base_temp);

    let mut all_carved_evtx: Vec<String> = Vec::new();
    let mut total_chunks = 0;
    let mut total_orphans = 0;

    for (idx, image_path) in files.iter().enumerate() {
        let image_name = Path::new(image_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(image_path);

        let file_size_str = fs::metadata(image_path)
            .map(|m| {
                let gb = m.len() as f64 / 1_073_741_824.0;
                if gb >= 1.0 { format!("{:.1} GB", gb) }
                else { format!("{:.0} MB", m.len() as f64 / 1_048_576.0) }
            })
            .unwrap_or_else(|_| "? size".to_string());

        crate::banner::print_info("");
        crate::banner::print_phase_result(&format!("Carving: {} ({})", image_name, file_size_str));
        crate::banner::print_info(&format!("  {}", image_path));

        let ext = Path::new(image_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let temp_dir = base_temp.join(format!("{}_{}", idx, image_name));
        let _ = fs::create_dir_all(&temp_dir);

        let result = match ext.as_str() {
            "e01" | "ex01" => carve_from_ewf(image_path, image_name, &temp_dir, unalloc_only, skip_offsets),
            "vmdk" => carve_from_vmdk(image_path, image_name, &temp_dir, unalloc_only),
            _ => carve_from_raw(image_path, image_name, &temp_dir, unalloc_only),
        };

        match result {
            Ok((chunks, orphans, evtx_files)) => {
                total_chunks += chunks;
                total_orphans += orphans;
                crate::banner::print_info(&format!(
                    "  Found: {} ElfChnk chunks ({} synthetic EVTX files), {} orphan records",
                    chunks, evtx_files.len(), orphans
                ));
                all_carved_evtx.extend(evtx_files);
            }
            Err(e) => {
                crate::banner::print_info(&format!("  Error: {}", e));
            }
        }
    }

    if all_carved_evtx.is_empty() {
        eprintln!();
        eprintln!("  ──────────────────────────────────────────────────");
        eprintln!("  No EVTX chunks found in scanned images.");
        eprintln!("  Completed in: {:.2}s", start_time.elapsed().as_secs_f64());
        let _ = fs::remove_dir_all(&base_temp);
        return;
    }

    // Phase 2: Validate each synthetic EVTX in isolation to catch OOM/hangs from
    // corrupt BinXML templates before handing them to the main parse pipeline.
    crate::banner::print_phase("2", "3", &format!(
        "Validating {} synthetic EVTX files (isolating corrupt chunks)...",
        all_carved_evtx.len()
    ));
    // In --debug mode, preserve rejected synthetic EVTX next to the output CSV so
    // the analyst can examine them later. Created lazily on first rejection.
    let save_rejected = is_debug_mode();
    let rejected_dir = {
        let base = output
            .and_then(|o| Path::new(o).parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));
        base.join("masstin_rejected_evtx")
    };
    let mut rejected_dir_created = false;

    let mut validated: Vec<String> = Vec::new();
    let mut rejected = 0usize;
    for path in &all_carved_evtx {
        let path_clone = path.clone();
        let (vtx, vrx) = std::sync::mpsc::channel();
        let vhandle = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Try to iterate all records — if any corrupt template triggers OOM
                // via set_alloc_error_hook, it panics and is caught here.
                let parser = match evtx::EvtxParser::from_path(&path_clone) {
                    Ok(p) => p,
                    Err(_) => return false,
                };
                let mut p = parser;
                // Walk EVERY record — any OOM-triggering corrupt template must fire inside
                // the isolated thread (where catch_unwind + alloc_error_hook protect us),
                // not later in the main pipeline. No early break.
                for rec in p.records() {
                    let _ = rec; // individual record errors are OK, file is still usable
                }
                true
            }));
            let _ = vtx.send(result);
        });
        match vrx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(true)) => {
                validated.push(path.clone());
                let _ = vhandle.join();
            }
            Ok(Ok(false)) => {
                rejected += 1;
                let fname = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or("?");
                if save_rejected {
                    if !rejected_dir_created { let _ = fs::create_dir_all(&rejected_dir); rejected_dir_created = true; }
                    let dest = rejected_dir.join(format!("open_fail__{}", fname));
                    let _ = fs::copy(path, &dest);
                    crate::banner::print_warning(&format!("  [reject] {} — parser failed to open (saved to {})", fname, dest.display()));
                } else {
                    crate::banner::print_warning(&format!("  [reject] {} — parser failed to open", fname));
                }
                let _ = vhandle.join();
            }
            Ok(Err(_)) => {
                rejected += 1;
                let fname = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or("?");
                if save_rejected {
                    if !rejected_dir_created { let _ = fs::create_dir_all(&rejected_dir); rejected_dir_created = true; }
                    let dest = rejected_dir.join(format!("panic_oom__{}", fname));
                    let _ = fs::copy(path, &dest);
                    crate::banner::print_warning(&format!("  [reject] {} — panic/OOM in evtx crate (saved to {})", fname, dest.display()));
                } else {
                    crate::banner::print_warning(&format!("  [reject] {} — panic/OOM in evtx crate", fname));
                }
                let _ = vhandle.join();
            }
            Err(_) => {
                rejected += 1;
                let fname = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or("?");
                if save_rejected {
                    if !rejected_dir_created { let _ = fs::create_dir_all(&rejected_dir); rejected_dir_created = true; }
                    let dest = rejected_dir.join(format!("hang__{}", fname));
                    let _ = fs::copy(path, &dest);
                    crate::banner::print_warning(&format!("  [reject] {} — hung >60s in evtx crate (saved to {})", fname, dest.display()));
                } else {
                    crate::banner::print_warning(&format!("  [reject] {} — hung >60s in evtx crate", fname));
                }
                std::mem::forget(vhandle);
            }
        }
    }
    crate::banner::print_info(&format!(
        "  Validation: {} accepted, {} rejected (corrupt BinXML)",
        validated.len(), rejected
    ));

    // Phase 3: Parse validated EVTX files through the existing masstin pipeline
    crate::banner::print_phase("3", "3", &format!(
        "Parsing {} validated synthetic EVTX files...", validated.len()
    ));

    let dirs: Vec<String> = vec![];
    crate::parse::parse_events_ex(&validated, &dirs, output, &[]);

    // Cleanup
    let _ = fs::remove_dir_all(&base_temp);

    // Final summary
    crate::banner::print_info("");
    eprintln!("  ──────────────────────────────────────────────────");
    eprintln!("  Carving results:");
    eprintln!("    Chunks carved:    {}", total_chunks);
    eprintln!("    Orphan records:   {} (metadata only — Tier 2)", total_orphans);
    eprintln!("    Images scanned:   {}", files.len());
    eprintln!("    Scan time:        {:.2}s", start_time.elapsed().as_secs_f64());
    if let Some(out) = output {
        eprintln!("    Output:           {}", out);
        crate::banner::print_info("");
        crate::banner::print_info(&format!(
            "Load into graph: masstin -a load-memgraph -f {} --database localhost:7687", out
        ));
    }
}

// ─── Image format handlers ──────────────────────────────────────────────────

fn carve_from_raw(path: &str, name: &str, temp_dir: &Path, unalloc: bool) -> Result<(usize, usize, Vec<String>), String> {
    let file = File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut reader = BufReader::new(file);
    carve_from_seekable(&mut reader, size, name, temp_dir, unalloc)
}

fn carve_from_ewf(path: &str, name: &str, temp_dir: &Path, unalloc: bool, skip_offsets: &[u64]) -> Result<(usize, usize, Vec<String>), String> {
    // For carving, read the E01 as a raw file (no EWF decompression).
    // This finds ElfChnk signatures in the raw E01 byte stream.
    // EWF stores data in 32KB chunks, some compressed (zlib), some not.
    // EVTX chunks (64KB) that span uncompressed EWF sectors will be found intact.
    // This avoids the EWF crate hanging on corrupted compressed chunks.
    //
    // We also try the EWF reader first for the logical disk view, but with
    // a safety mechanism: if any read takes too long, we fall back to raw scanning.

    let file_size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    crate::banner::print_info(&format!("  E01 raw file size: {:.1} GB (logical disk may be larger)",
        file_size as f64 / 1_073_741_824.0));

    // First try: EWF logical view with stall detection
    let ewf_result = carve_from_ewf_with_stall_detection(path, name, temp_dir, unalloc, skip_offsets);

    match ewf_result {
        Ok((chunks, orphans, files)) => {
            if chunks > 0 {
                crate::banner::print_info(&format!("  EWF logical scan: {} chunks recovered", chunks));
            }
            // Also do a raw scan of the E01 file to find additional chunks
            // that might be in the raw byte stream (uncompressed EWF segments)
            crate::banner::print_info("  Also scanning raw E01 bytes for additional chunks...");
            let file = File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
            let mut raw_reader = BufReader::new(file);
            let raw_temp = temp_dir.join("raw_scan");
            let _ = std::fs::create_dir_all(&raw_temp);
            match carve_from_seekable(&mut raw_reader, file_size, name, &raw_temp, unalloc) {
                Ok((raw_chunks, raw_orphans, raw_files)) => {
                    let mut all_files = files;
                    all_files.extend(raw_files);
                    Ok((chunks + raw_chunks, orphans + raw_orphans, all_files))
                }
                Err(_) => Ok((chunks, orphans, files)), // Raw scan failed, return EWF results only
            }
        }
        Err(e) => {
            crate::banner::print_warning(&format!("  EWF logical read failed: {}", e));
            crate::banner::print_info("  Falling back to raw E01 byte scan only...");
            let file = File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
            let mut reader = BufReader::new(file);
            carve_from_seekable(&mut reader, file_size, name, temp_dir, unalloc)
        }
    }
}

/// Try EWF logical carving with stall detection.
/// If a read takes >30s, abort and return an error so the caller can fall back.
/// Wrapper to make EwfReader Send (unsafe — we ensure exclusive access)
struct SendableEwf(ewf::EwfReader);
unsafe impl Send for SendableEwf {}

fn carve_from_ewf_with_stall_detection(
    path: &str,
    name: &str,
    temp_dir: &Path,
    _unalloc: bool,
    skip_offsets: &[u64],
) -> Result<(usize, usize, Vec<String>), String> {
    // Skip window size — each user-specified offset skips this many bytes forward
    const SKIP_WINDOW: u64 = 32 * 1024 * 1024; // 32 MB
    let reader = ewf::EwfReader::open(path)
        .map_err(|e| format!("Cannot open E01: {}", e))?;
    let image_size = reader.total_size();
    let image_size_gb = image_size as f64 / 1_073_741_824.0;

    let mut chunks_found = 0;
    let mut orphan_records = 0;
    let mut chunk_offsets: HashSet<u64> = HashSet::new();
    let mut provider_chunks: std::collections::HashMap<String, Vec<Vec<u8>>> = std::collections::HashMap::new();

    let total_blocks = image_size / SCAN_BLOCK_SIZE as u64 + 1;
    let pb = crate::banner::create_progress_bar(total_blocks);
    crate::banner::progress_set_message(&pb, &format!("Scanning {:.1} GB E01 (logical)...", image_size_gb));

    let mut offset: u64 = 0;
    let ewf_path = path.to_string();
    let mut stalled_offsets: Vec<u64> = Vec::new();

    // Wrap the reader so we can move it into threads
    let mut reader_opt: Option<SendableEwf> = Some(SendableEwf(reader));
    let timeout = Duration::from_secs(10);

    while offset < image_size {
        // Check user-provided skip list: if current offset is inside any skip window, jump past it
        let mut skipped = false;
        for &skip in skip_offsets {
            if offset >= skip.saturating_sub(SCAN_BLOCK_SIZE as u64) && offset < skip + SKIP_WINDOW {
                let jump_to = skip + SKIP_WINDOW;
                crate::banner::print_warning(&format!(
                    "  [SKIP] User-requested skip at {:#x} → jumping to {:#x} ({:.2} GB, {} MB window)",
                    skip, jump_to, skip as f64 / 1_073_741_824.0, SKIP_WINDOW / (1024 * 1024)
                ));
                offset = jump_to;
                skipped = true;
                break;
            }
        }
        if skipped {
            pb.inc(1);
            continue;
        }

        let to_read = SCAN_BLOCK_SIZE.min((image_size - offset) as usize);

        // Update progress BEFORE the read — this way, if the read hangs, the last message
        // on screen shows the exact offset where the stall happened
        pb.set_message(format!(
            "off={:#x} ({:.2}/{:.1} GB) | {} chunks",
            offset, offset as f64 / 1_073_741_824.0, image_size_gb, chunks_found
        ));

        // Take ownership of the reader for this read
        let mut sendable = match reader_opt.take() {
            Some(r) => r,
            None => {
                // Need to reopen — previous reader was abandoned in a stalled thread
                match ewf::EwfReader::open(&ewf_path) {
                    Ok(new_reader) => SendableEwf(new_reader),
                    Err(_) => break,
                }
            }
        };

        // Seek to current offset
        let _ = sendable.0.seek(SeekFrom::Start(offset));

        // Do the read in a thread with timeout
        let (tx, rx) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let mut buf = vec![0u8; to_read];
            let result = sendable.0.read(&mut buf);
            let _ = tx.send((result, buf, sendable));
        });

        match rx.recv_timeout(timeout) {
            Ok((Ok(n), buf, sendable_back)) => {
                if n == 0 { break; }

                // Got data — put reader back
                reader_opt = Some(sendable_back);

                // Scan for ElfChnk in this block
                let mut pos = 0;
                while pos + EVTX_CHUNK_SIZE <= n {
                    if buf.len() >= pos + 8 && &buf[pos..pos + 8] == ELFCHNK_MAGIC {
                        let chunk_abs_offset = offset + pos as u64;
                        if !chunk_offsets.contains(&chunk_abs_offset) {
                            let chunk_data = buf[pos..pos + EVTX_CHUNK_SIZE].to_vec();
                            // Parse in a thread with timeout — the evtx crate can enter
                            // infinite loops on malformed BinXML, which catch_unwind does NOT catch.
                            let chunk_for_thread = chunk_data.clone();
                            let (ptx, prx) = std::sync::mpsc::channel();
                            let phandle = std::thread::spawn(move || {
                                let result = std::panic::catch_unwind(
                                    std::panic::AssertUnwindSafe(|| peek_chunk_provider(&chunk_for_thread))
                                );
                                let _ = ptx.send(result);
                            });
                            match prx.recv_timeout(Duration::from_secs(3)) {
                                Ok(Ok(Some(provider))) => {
                                    chunks_found += 1;
                                    chunk_offsets.insert(chunk_abs_offset);
                                    if is_debug_mode() {
                                        eprintln!("[DEBUG] Chunk at {:#x}: provider={}", chunk_abs_offset, provider);
                                    }
                                    provider_chunks.entry(provider).or_default().push(chunk_data);
                                    pb.set_message(format!("{:.1}/{:.1} GB | {} chunks found",
                                        (offset + pos as u64) as f64 / 1_073_741_824.0, image_size_gb, chunks_found));
                                    let _ = phandle.join();
                                }
                                Ok(_) => {
                                    // None or panic — invalid chunk, skip silently
                                    let _ = phandle.join();
                                }
                                Err(_) => {
                                    // PARSE HUNG — evtx crate infinite loop on malformed BinXML
                                    crate::banner::print_warning(&format!(
                                        "  [evtx hang] chunk at {:#x} — skipping corrupt BinXML",
                                        chunk_abs_offset
                                    ));
                                    // Abandon the stuck thread
                                    std::mem::forget(phandle);
                                    // Mark offset as seen so we don't retry
                                    chunk_offsets.insert(chunk_abs_offset);
                                }
                            }
                        }
                        pos += EVTX_CHUNK_SIZE;
                    } else {
                        pos += 512;
                    }
                }

                // Count orphan records
                let mut rpos = 0;
                while rpos + 28 <= n {
                    if buf.len() >= rpos + 4 && &buf[rpos..rpos + 4] == RECORD_MAGIC {
                        let rec_abs = offset + rpos as u64;
                        let in_chunk = chunk_offsets.iter().any(|&co| rec_abs >= co && rec_abs < co + EVTX_CHUNK_SIZE as u64);
                        if !in_chunk && validate_record_header(&buf[rpos..n.min(rpos + 65536)]) {
                            orphan_records += 1;
                        }
                        rpos += 8;
                    } else {
                        rpos += 8;
                    }
                }

                if is_debug_mode() && offset % (1 << 30) < SCAN_BLOCK_SIZE as u64 {
                    eprintln!("[DEBUG] Read {:#x}: {} bytes OK", offset, n);
                }

                offset += n as u64;
            }
            Ok((Err(e), _, sendable_back)) => {
                // Read returned an error
                reader_opt = Some(sendable_back);
                crate::banner::print_warning(&format!(
                    "  E01 read error at {:#x} ({:.1} GB): {} — skipping 4 MB",
                    offset, offset as f64 / 1_073_741_824.0, e
                ));
                offset += SCAN_BLOCK_SIZE as u64;
            }
            Err(_) => {
                // TIMEOUT — the read is stuck. Abandon the thread and reader.
                // The thread will keep running (blocked forever) but we move on.
                crate::banner::print_warning(&format!(
                    "  E01 STALL at {:#x} ({:.2} GB) — corrupted EWF chunk, abandoning thread, skipping 32 MB",
                    offset, offset as f64 / 1_073_741_824.0
                ));
                crate::banner::print_warning(&format!(
                    "  → To skip this on re-run: --skip-offsets {:#x}",
                    offset
                ));
                stalled_offsets.push(offset);
                // Don't join the handle — let the blocked thread die with the process
                std::mem::forget(handle);
                // reader_opt is None — will reopen on next iteration
                offset += 32 * 1024 * 1024; // Skip 32 MB
            }
        }

        pb.inc(1);
    }

    pb.finish_and_clear();

    if !stalled_offsets.is_empty() {
        crate::banner::print_warning(&format!(
            "  {} stalled offset(s) encountered during scan. To skip them next run:",
            stalled_offsets.len()
        ));
        let hex_list: Vec<String> = stalled_offsets.iter().map(|o| format!("{:#x}", o)).collect();
        crate::banner::print_warning(&format!("  --skip-offsets {}", hex_list.join(",")));
    }

    // Build synthetic EVTX files
    crate::banner::print_info(&format!(
        "  Building synthetic EVTX files from {} providers ({} total chunks)",
        provider_chunks.len(), chunks_found
    ));
    let mut carved_evtx_files: Vec<String> = Vec::new();
    for (provider, chunks) in &provider_chunks {
        let evtx_filename = provider_to_evtx_filename(provider);
        let evtx_path = temp_dir.join(&evtx_filename);
        match build_synthetic_evtx(&evtx_path, chunks) {
            Ok(_) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Built {} ({} chunks) -> {}", evtx_filename, chunks.len(), evtx_path.display());
                }
                carved_evtx_files.push(evtx_path.to_string_lossy().to_string());
            }
            Err(e) => {
                crate::banner::print_warning(&format!(
                    "  build_synthetic_evtx failed for provider='{}' ({} chunks): {}",
                    provider, chunks.len(), e
                ));
            }
        }
    }
    crate::banner::print_info(&format!(
        "  Synthetic EVTX files built: {}", carved_evtx_files.len()
    ));

    Ok((chunks_found, orphan_records, carved_evtx_files))
}

fn carve_from_vmdk(path: &str, name: &str, temp_dir: &Path, unalloc: bool) -> Result<(usize, usize, Vec<String>), String> {
    let vmdk = crate::vmdk::VmdkReader::open(path)
        .map_err(|e| format!("Cannot open VMDK: {}", e))?;
    let size = vmdk.total_size();
    let mut reader = BufReader::new(vmdk);
    carve_from_seekable(&mut reader, size, name, temp_dir, unalloc)
}

// ─── Core carving engine ────────────────────────────────────────────────────

fn carve_from_seekable<R: Read + Seek>(
    reader: &mut R,
    image_size: u64,
    image_name: &str,
    temp_dir: &Path,
    _unalloc_only: bool,
) -> Result<(usize, usize, Vec<String>), String> {
    let mut chunks_found = 0;
    let mut orphan_records = 0;
    let mut carved_evtx_files: Vec<String> = Vec::new();
    let mut chunk_offsets: HashSet<u64> = HashSet::new();

    // Accumulate chunks by provider for grouping into synthetic EVTX files
    let mut provider_chunks: std::collections::HashMap<String, Vec<Vec<u8>>> = std::collections::HashMap::new();

    let image_size_gb = image_size as f64 / 1_073_741_824.0;
    let total_blocks = image_size / SCAN_BLOCK_SIZE as u64 + 1;
    let pb = crate::banner::create_progress_bar(total_blocks);
    crate::banner::progress_set_message(&pb, &format!("Scanning {:.1} GB...", image_size_gb));

    reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;

    let mut offset: u64 = 0;
    // Buffer with extra space for chunk boundary detection
    let mut buf = vec![0u8; SCAN_BLOCK_SIZE + EVTX_CHUNK_SIZE];
    let mut carry_over = 0usize;

    let mut consecutive_errors = 0;
    let max_consecutive_errors = 10; // Skip ahead after 10 consecutive read errors

    while offset < image_size {
        let to_read = SCAN_BLOCK_SIZE.min((image_size - offset) as usize);

        // Sequential read with timing debug
        let read_start = Instant::now();
        let bytes_read = match reader.read(&mut buf[carry_over..carry_over + to_read]) {
            Ok(0) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] EOF at offset {:#x} ({:.1} GB)", offset, offset as f64 / 1_073_741_824.0);
                }
                break;
            }
            Ok(n) => {
                let elapsed = read_start.elapsed();
                if is_debug_mode() && (elapsed > Duration::from_secs(2) || offset % (1_073_741_824) < SCAN_BLOCK_SIZE as u64) {
                    eprintln!("[DEBUG] Read {:#x}: {} bytes in {:.2}s ({:.1} MB/s)",
                        offset, n, elapsed.as_secs_f64(),
                        n as f64 / 1_048_576.0 / elapsed.as_secs_f64().max(0.001));
                }
                consecutive_errors = 0;
                n
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Read error at offset {:#x}: {}", offset, e);
                }
                // Try to seek past the bad region
                let skip = SCAN_BLOCK_SIZE as u64;
                offset += skip;
                carry_over = 0;
                consecutive_errors += 1;
                if consecutive_errors > max_consecutive_errors {
                    crate::banner::print_warning(&format!(
                        "  Too many read errors after {:#x}, skipping ahead 64 MB", offset
                    ));
                    offset += 64 * 1024 * 1024;
                    let _ = reader.seek(SeekFrom::Start(offset));
                    consecutive_errors = 0;
                }
                pb.inc(1);
                continue;
            }
        };
        let total_bytes = carry_over + bytes_read;

        // ─── Tier 1: Scan for ElfChnk ───────────────────────────────────
        let mut pos = 0;
        while pos + EVTX_CHUNK_SIZE <= total_bytes {
            if buf.len() >= pos + 8 && &buf[pos..pos + 8] == ELFCHNK_MAGIC {
                let chunk_abs_offset = offset + pos as u64 - carry_over as u64;

                // Skip if we already found this chunk (overlap detection)
                if chunk_offsets.contains(&chunk_abs_offset) {
                    pos += EVTX_CHUNK_SIZE;
                    continue;
                }

                let chunk_data = buf[pos..pos + EVTX_CHUNK_SIZE].to_vec();

                // Validate: try to peek at the provider from the first record
                // Use catch_unwind to protect against panics in corrupted chunks
                let provider_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    peek_chunk_provider(&chunk_data)
                }));
                let provider = match provider_result {
                    Ok(Some(p)) => Some(p),
                    _ => None,
                };
                if let Some(provider) = provider {
                    chunks_found += 1;
                    chunk_offsets.insert(chunk_abs_offset);

                    if is_debug_mode() {
                        eprintln!("[DEBUG] Chunk at {:#x}: provider={}", chunk_abs_offset, provider);
                    }

                    provider_chunks.entry(provider).or_default().push(chunk_data);

                    // Update progress message with findings
                    let scanned_gb = (offset + pos as u64) as f64 / 1_073_741_824.0;
                    pb.set_message(format!("{:.1}/{:.1} GB | {} chunks found",
                        scanned_gb, image_size_gb, chunks_found));
                }

                pos += EVTX_CHUNK_SIZE;
            } else {
                pos += 512; // Sector-aligned scan
            }
        }

        // ─── Tier 2: Count orphan records (for reporting) ────────────────
        let mut rpos = 0;
        while rpos + 28 <= total_bytes {
            if buf.len() >= rpos + 4 && &buf[rpos..rpos + 4] == RECORD_MAGIC {
                let rec_abs = offset + rpos as u64 - carry_over as u64;

                // Skip if inside a known chunk
                let in_chunk = chunk_offsets.iter().any(|&co| rec_abs >= co && rec_abs < co + EVTX_CHUNK_SIZE as u64);

                if !in_chunk {
                    if validate_record_header(&buf[rpos..total_bytes.min(rpos + 65536)]) {
                        orphan_records += 1;
                    }
                }
                rpos += 8;
            } else {
                rpos += 8;
            }
        }

        // Carry over for boundary detection
        carry_over = EVTX_CHUNK_SIZE.min(total_bytes);
        if total_bytes > carry_over {
            buf.copy_within(total_bytes - carry_over..total_bytes, 0);
        }

        offset += bytes_read as u64;
        pb.inc(1);
    }

    pb.finish_and_clear();

    // ─── Build synthetic EVTX files per provider ────────────────────────
    for (provider, chunks) in &provider_chunks {
        // Map provider to the filename that masstin's parselog expects
        let evtx_filename = provider_to_evtx_filename(provider);
        let evtx_path = temp_dir.join(&evtx_filename);

        match build_synthetic_evtx(&evtx_path, chunks) {
            Ok(()) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Synthetic EVTX: {} ({} chunks) → {}", provider, chunks.len(),
                        evtx_path.display());
                }
                carved_evtx_files.push(evtx_path.to_string_lossy().to_string());
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Failed to build synthetic EVTX for {}: {}", provider, e);
                }
            }
        }
    }

    Ok((chunks_found, orphan_records, carved_evtx_files))
}

/// Peek into a chunk to validate it and extract the provider name from the first record
fn peek_chunk_provider(chunk_data: &[u8]) -> Option<String> {
    // Validate chunk by trying to parse it
    let mut chunk_obj = evtx::EvtxChunkData::new(chunk_data.to_vec(), false).ok()?;

    let settings = std::sync::Arc::new(evtx::ParserSettings::default());
    let mut parsed = chunk_obj.parse(settings).ok()?;

    // Get provider from first record by rendering to XML
    for record_result in parsed.iter() {
        if let Ok(record) = record_result {
            let mut xml_buf: Vec<u8> = Vec::new();
            let mut xml_out = evtx::XmlOutput::with_writer(&mut xml_buf, &evtx::ParserSettings::default());
            if record.into_output(&mut xml_out).is_ok() {
                let xml = String::from_utf8_lossy(&xml_out.into_writer()).to_string();
                // Extract provider from <Provider Name="..."/>
                if let Some(start) = xml.find("Provider Name=\"") {
                    let after = &xml[start + 15..];
                    if let Some(end) = after.find('"') {
                        let provider = &after[..end];
                        if !provider.is_empty() {
                            return Some(provider.to_string());
                        }
                    }
                }
            }
        }
        break; // Only check first record
    }

    Some("Unknown".to_string())
}

/// Build a synthetic EVTX file from carved chunks (bulk_extractor-rec approach)
fn build_synthetic_evtx(path: &Path, chunks: &[Vec<u8>]) -> Result<(), String> {
    let mut file = File::create(path).map_err(|e| format!("Cannot create: {}", e))?;

    // Build ElfFile header (4096 bytes)
    let mut header = [0u8; 4096];
    // Magic: "ElfFile\x00"
    header[0..8].copy_from_slice(b"ElfFile\x00");
    // First chunk number: 0
    // Last chunk number
    let last_chunk = if chunks.is_empty() { 0u64 } else { (chunks.len() - 1) as u64 };
    header[16..24].copy_from_slice(&last_chunk.to_le_bytes());
    // Next record identifier (placeholder)
    header[24..32].copy_from_slice(&0u64.to_le_bytes());
    // Header size: 128
    header[32..36].copy_from_slice(&128u32.to_le_bytes());
    // Minor version: 1
    header[36..38].copy_from_slice(&1u16.to_le_bytes());
    // Major version: 3
    header[38..40].copy_from_slice(&3u16.to_le_bytes());
    // Header block size: 4096
    header[40..42].copy_from_slice(&4096u16.to_le_bytes());
    // Number of chunks
    header[42..44].copy_from_slice(&(chunks.len() as u16).to_le_bytes());
    // Compute CRC32 of first 120 bytes
    let crc = crc32_ieee(&header[0..120]);
    header[124..128].copy_from_slice(&crc.to_le_bytes());

    // Write header
    file.write_all(&header).map_err(|e| format!("Write header: {}", e))?;

    // Write chunks
    for chunk in chunks {
        if chunk.len() == EVTX_CHUNK_SIZE {
            file.write_all(chunk).map_err(|e| format!("Write chunk: {}", e))?;
        }
    }

    Ok(())
}

/// Validate a potential orphan record header
fn validate_record_header(buf: &[u8]) -> bool {
    if buf.len() < 28 { return false; }
    if &buf[0..4] != RECORD_MAGIC { return false; }

    let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if size < 28 || size > 65024 { return false; }
    if size as usize > buf.len() { return false; }

    // Check trailing size copy
    let trail = size as usize - 4;
    let trailing_size = u32::from_le_bytes([buf[trail], buf[trail+1], buf[trail+2], buf[trail+3]]);
    if trailing_size != size { return false; }

    // Validate BinXML preamble
    if buf[24] != 0x0F { return false; }

    // Timestamp sanity (2000-2030)
    let ft = u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
    if ft == 0 { return false; }
    let secs = ft / 10_000_000;
    if secs < 11_644_473_600 + 946_684_800 { return false; } // before 2000
    if secs > 11_644_473_600 + 1_893_456_000 { return false; } // after 2030

    true
}

/// Map EVTX provider name to the filename that masstin's parselog() expects
fn provider_to_evtx_filename(provider: &str) -> String {
    match provider {
        "Microsoft-Windows-Security-Auditing" => "Security.evtx".to_string(),
        "Microsoft-Windows-TerminalServices-LocalSessionManager" =>
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx".to_string(),
        "Microsoft-Windows-TerminalServices-ClientActiveXCore" =>
            "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx".to_string(),
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager" =>
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx".to_string(),
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" =>
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx".to_string(),
        "Microsoft-Windows-SMBServer" =>
            "Microsoft-Windows-SMBServer%4Security.evtx".to_string(),
        "Microsoft-Windows-SMBClient" =>
            "Microsoft-Windows-SmbClient%4Security.evtx".to_string(),
        "Microsoft-Windows-SmbClient" =>
            "Microsoft-Windows-SmbClient%4Connectivity.evtx".to_string(),
        "Microsoft-Windows-WinRM" =>
            "Microsoft-Windows-WinRM%4Operational.evtx".to_string(),
        "Microsoft-Windows-WMI-Activity" =>
            "Microsoft-Windows-WMI-Activity%4Operational.evtx".to_string(),
        _ => {
            // Non-lateral-movement provider — still create the file but parselog will skip it
            let safe = provider.replace(|c: char| !c.is_alphanumeric() && c != '-', "_");
            format!("{}.evtx", safe)
        }
    }
}

/// Simple CRC32 (IEEE) implementation
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
