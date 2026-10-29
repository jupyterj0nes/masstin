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

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use blockcarve::evtx::{chunk_checksums_ok, orphan_record, ChunkGroups, CHUNK_MAGIC, CHUNK_SIZE};
use blockcarve::scan::{scan_many, HitAction, ScanConfig, BLOCK_SIZE};
use blockcarve::source::{BlockError, BlockSource, DirectSource, GuardedSource};

use crate::parse::is_debug_mode;

/// Child-process entry: open a single EVTX and iterate every record.
/// Returns true iff the file parses cleanly end-to-end. Called only via
/// the `MASSTIN_VALIDATE_EVTX` env var from `main.rs`; parse-carve spawns
/// a child per synthetic EVTX so that any `alloc_error`-driven abort from
/// a corrupt BinXML template only kills the child — the parent sees a
/// non-zero exit code and rejects the file. `catch_unwind` still covers
/// ordinary panics inside the child.
pub fn validate_evtx_file(path: &str) -> bool {
    let result = std::panic::catch_unwind(|| {
        let parser = match evtx::EvtxParser::from_path(path) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let mut p = parser;
        for rec in p.records() {
            let _ = rec;
        }
        true
    });
    matches!(result, Ok(true))
}

/// Time budget for one block read on an EWF image before the reader is abandoned.
const EWF_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bytes jumped past every `--skip-offsets` entry.
const SKIP_WINDOW: u64 = 32 * 1024 * 1024;

/// Main entry point for carve-image action.
///
/// Historical note on OOM isolation: prior to the evtx 0.11.2 upgrade,
/// carve-image relied on a nightly-only `set_alloc_error_hook` to survive
/// pathological chunks where the upstream parser attempted multi-GB
/// allocations on corrupt BinXML template size fields (issues
/// omerbenamram/evtx#290, #291, #292). evtx 0.11.2 bounds *some* of those
/// operations, but NOT the template-values count read by
/// `read_template_values_cursor`: a corrupt u32 there still drives a
/// `Vec::with_capacity(N)` of several GiB, which the global allocator
/// resolves by calling `abort()`. That abort is not a Rust panic and is
/// therefore invisible to `catch_unwind` / thread isolation, and it is
/// amplified by rayon (the crate parallelises chunk decoding, so the
/// abort can fire in a worker pool the parent never sees).
///
/// Defence today is subprocess isolation: phase 2 spawns this same binary
/// per synthetic EVTX via `MASSTIN_VALIDATE_EVTX=<path>` (see main.rs).
/// If the child aborts by OOM, the parent observes a non-zero exit code
/// and rejects the file. The 60-second per-file timeout,
/// `--skip-offsets` escape hatch, and in-child `catch_unwind` still cover
/// the non-allocation panic paths.
pub fn carve_image(files: &[String], output: Option<&String>, unalloc_only: bool, skip_offsets: &[u64]) {
    let start_time = std::time::Instant::now();

    crate::banner::print_phase("1", "3", "Scanning forensic images for EVTX remnants...");

    if unalloc_only {
        crate::banner::print_warning("  --carve-unalloc is not implemented yet: scanning the whole image");
    }
    crate::banner::print_info("  Mode: full disk scan");

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

        let result = carve_path(image_path, &ext, image_name, &temp_dir, skip_offsets);

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

    // Each synthetic EVTX is validated in a dedicated child process invoking
    // the same binary with MASSTIN_VALIDATE_EVTX=<path>. Subprocess isolation
    // is the only way to survive `alloc_error` aborts from corrupt BinXML
    // templates (the `evtx` crate reserves Vec capacity from template-value
    // counts without bounds, and rayon workers amplify the blast radius — a
    // single bad chunk can try to allocate ~16 GiB and crash the whole
    // process). catch_unwind + thread isolation cannot catch that.
    let exe = std::env::current_exe().ok();
    for path in &all_carved_evtx {
        let fname = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or("?");

        let Some(exe) = exe.as_ref() else {
            rejected += 1;
            crate::banner::print_warning(&format!(
                "  [reject] {} — cannot locate current executable to spawn validator", fname
            ));
            continue;
        };

        let mut child = match Command::new(exe)
            .env("MASSTIN_VALIDATE_EVTX", path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                rejected += 1;
                crate::banner::print_warning(&format!(
                    "  [reject] {} — could not spawn validator: {}", fname, e
                ));
                continue;
            }
        };

        // Poll every 50 ms up to a 60 s deadline.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break None,
            }
        };

        match (status, timed_out) {
            (Some(s), _) if s.success() => {
                validated.push(path.clone());
            }
            (Some(s), _) => {
                rejected += 1;
                let code_str = s
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "terminated by signal".to_string());
                if save_rejected {
                    if !rejected_dir_created { let _ = fs::create_dir_all(&rejected_dir); rejected_dir_created = true; }
                    let dest = rejected_dir.join(format!("panic_oom__{}", fname));
                    let _ = fs::copy(path, &dest);
                    crate::banner::print_warning(&format!(
                        "  [reject] {} — validator exit={} (OOM/panic, saved to {})",
                        fname, code_str, dest.display()
                    ));
                } else {
                    crate::banner::print_warning(&format!(
                        "  [reject] {} — validator exit={} (OOM/panic)", fname, code_str
                    ));
                }
            }
            (None, true) => {
                rejected += 1;
                if save_rejected {
                    if !rejected_dir_created { let _ = fs::create_dir_all(&rejected_dir); rejected_dir_created = true; }
                    let dest = rejected_dir.join(format!("hang__{}", fname));
                    let _ = fs::copy(path, &dest);
                    crate::banner::print_warning(&format!(
                        "  [reject] {} — hung >60s (killed, saved to {})", fname, dest.display()
                    ));
                } else {
                    crate::banner::print_warning(&format!(
                        "  [reject] {} — hung >60s (killed)", fname
                    ));
                }
            }
            (None, false) => {
                rejected += 1;
                crate::banner::print_warning(&format!(
                    "  [reject] {} — validator wait failed", fname
                ));
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
    crate::parse::parse_events_ex(&validated, &dirs, output, &[], &[]);

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
        let pretty = crate::banner::normalize_display_path(out);
        eprintln!("    Output:           {}", pretty);
        crate::banner::print_info("");
        crate::banner::print_info("Load into graph (pick one):");
        crate::banner::print_info(&format!(
            "  Memgraph:  masstin -a load-memgraph -f {} --database localhost:7687", pretty
        ));
        crate::banner::print_info(&format!(
            "  Neo4j:     masstin -a load-neo4j   -f {} --database bolt://localhost:7687 --user neo4j", pretty
        ));
    }
}

// ─── Sources and the carving engine (blockcarve) ────────────────────────────

/// `ewf::EwfReader` holds an `Rc` cache and is not `Send`; the guarded source
/// moves the reader into a helper thread for every read and back again, so it
/// is only ever used by one thread at a time.
struct SendableEwf(ewf::EwfReader);
// SAFETY: the reader is owned by exactly one thread at any moment (the helper
// thread during a read, the caller otherwise); nothing is shared concurrently.
unsafe impl Send for SendableEwf {}

impl Read for SendableEwf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for SendableEwf {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

/// A source with `--skip-offsets` applied: every block that touches a window of
/// [`SKIP_WINDOW`] bytes after a listed offset is served as zeros without
/// touching the reader, so a region known to hang the EWF decoder is never read.
struct SkipWindows {
    inner: Box<dyn BlockSource>,
    skips: Vec<u64>,
}

impl BlockSource for SkipWindows {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn stalls(&self) -> usize {
        self.inner.stalls()
    }

    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        let end = offset + len as u64;
        if self.skips.iter().any(|&s| offset < s + SKIP_WINDOW && end > s.saturating_sub(BLOCK_SIZE as u64)) {
            let len = len.min(self.size().saturating_sub(offset) as usize);
            return Ok(vec![0u8; len]);
        }
        self.inner.read_block(offset, len)
    }
}

/// Opens an image by extension: EWF through a guarded reader (a stuck read is
/// abandoned and the reader reopened), VMDK, VHD/VHDX and raw files directly.
fn open_source(path: &str, ext: &str) -> Result<Box<dyn BlockSource>, String> {
    match ext {
        "e01" | "ex01" => {
            let reader = ewf::EwfReader::open(path).map_err(|e| format!("Cannot open E01: {}", e))?;
            let size = reader.total_size();
            let reopen = path.to_string();
            Ok(Box::new(GuardedSource::new(SendableEwf(reader), size, path.to_string(), EWF_READ_TIMEOUT, move || {
                ewf::EwfReader::open(&reopen).map(SendableEwf).map_err(|e| e.to_string())
            })))
        }
        "vmdk" => {
            let vmdk = crate::vmdk::VmdkReader::open(path).map_err(|e| format!("Cannot open VMDK: {}", e))?;
            let size = vmdk.total_size();
            Ok(Box::new(DirectSource::new(vmdk, size, path.to_string())))
        }
        "vhd" | "vhdx" => {
            let (disk, size) = crate::vhd::open_virtual_disk(path).map_err(|e| format!("Cannot open virtual disk: {}", e))?;
            Ok(Box::new(DirectSource::new(disk, size, path.to_string())))
        }
        _ => blockcarve::source::open_file(Path::new(path)),
    }
}

/// Carves one image: the logical view first; for an EWF image whose decoder
/// stalled or failed, the raw bytes of the container file as well (chunks in
/// uncompressed segments are still found there).
fn carve_path(path: &str, ext: &str, name: &str, temp_dir: &Path, skip_offsets: &[u64]) -> Result<(usize, usize, Vec<String>), String> {
    let mut src: Box<dyn BlockSource> = match open_source(path, ext) {
        Ok(s) if skip_offsets.is_empty() => s,
        Ok(s) => Box::new(SkipWindows { inner: s, skips: skip_offsets.to_vec() }),
        Err(e) if matches!(ext, "e01" | "ex01") => {
            crate::banner::print_warning(&format!("  EWF logical read failed: {}", e));
            crate::banner::print_info("  Falling back to raw E01 byte scan only...");
            blockcarve::source::open_file(Path::new(path))?
        }
        Err(e) => return Err(e),
    };
    let (mut chunks, mut orphans, mut files, troubled) = carve_source(&mut *src, name, temp_dir)?;
    if troubled && matches!(ext, "e01" | "ex01") {
        crate::banner::print_info("  Also scanning raw E01 bytes for additional chunks...");
        let mut raw = blockcarve::source::open_file(Path::new(path))?;
        let raw_temp = temp_dir.join("raw_scan");
        if let Ok((c, o, f, _)) = carve_source(&mut *raw, name, &raw_temp) {
            chunks += c;
            orphans += o;
            files.extend(f);
        }
    }
    Ok((chunks, orphans, files))
}

/// Scans a source for `ElfChnk` chunks (accepted on their checksums, named by
/// the provider of their first record) and counts orphan records outside them.
/// Returns `(chunks, orphan records, synthetic files, scan had stalls or errors)`.
fn carve_source(src: &mut dyn BlockSource, image_name: &str, temp_dir: &Path) -> Result<(usize, usize, Vec<String>, bool), String> {
    let image_size = src.size();
    let image_size_gb = image_size as f64 / 1_073_741_824.0;
    let pb = crate::banner::create_progress_bar(image_size / BLOCK_SIZE as u64 + 1);
    crate::banner::progress_set_message(&pb, &format!("Scanning {:.1} GB...", image_size_gb));

    let mut groups = ChunkGroups::default();
    let mut chunks_found = 0usize;
    let mut orphan_records = 0usize;
    // ranges of accepted chunks: a record inside one is not an orphan
    let chunk_ranges: std::cell::RefCell<Vec<(u64, u64)>> = std::cell::RefCell::new(Vec::new());
    let mut hung = 0usize;

    let cfg = ScanConfig { window: CHUNK_SIZE, ..Default::default() };
    let mut on_hit = |_src: &mut dyn BlockSource, offset: u64, window: &[u8], _which: usize| -> HitAction {
        if window.len() < CHUNK_SIZE || !chunk_checksums_ok(&window[..CHUNK_SIZE]) {
            return HitAction::Continue;
        }
        let chunk = window[..CHUNK_SIZE].to_vec();
        chunk_ranges.borrow_mut().push((offset, offset + CHUNK_SIZE as u64));
        let provider = match peek_with_timeout(&chunk) {
            Peek::Provider(p) => p,
            Peek::Invalid => return HitAction::SkipTo(offset + CHUNK_SIZE as u64),
            Peek::Hung => {
                hung += 1;
                crate::banner::print_warning(&format!("  [evtx hang] chunk at {:#x} — skipping corrupt BinXML", offset));
                return HitAction::SkipTo(offset + CHUNK_SIZE as u64);
            }
        };
        if groups.add(provider.clone(), offset, chunk) {
            chunks_found += 1;
            if is_debug_mode() {
                eprintln!("[DEBUG] Chunk at {:#x}: provider={}", offset, provider);
            }
            pb.set_message(format!("{:.1}/{:.1} GB | {} chunks found", offset as f64 / 1_073_741_824.0, image_size_gb, chunks_found));
        }
        HitAction::SkipTo(offset + CHUNK_SIZE as u64)
    };
    let mut on_block = |base: u64, block: &[u8]| {
        let mut pos = 0usize;
        while pos + 28 <= block.len() {
            let b = &block[pos..];
            if b[0] == 0x2a && b[1] == 0x2a && b[2] == 0 && b[3] == 0 {
                let abs = base + pos as u64;
                if !chunk_ranges.borrow().iter().any(|&(s, e)| abs >= s && abs < e) {
                    if let Some((_, _, size)) = orphan_record(b) {
                        orphan_records += 1;
                        pos += (size as usize).max(8) & !7;
                        continue;
                    }
                }
            }
            pos += 8;
        }
    };
    let mut on_progress = |offset: u64, _size: u64| pb.set_position(offset / BLOCK_SIZE as u64);
    let stats = scan_many(src, &cfg, &[CHUNK_MAGIC], &mut on_hit, &mut on_progress, Some(&mut on_block));
    pb.finish_and_clear();

    for note in stats.notes.iter().take(10) {
        crate::banner::print_warning(&format!("  {}", note));
    }
    if stats.stalls > 0 {
        crate::banner::print_warning(&format!(
            "  {} stalled read(s) on {}: the reader was reopened and 32 MB skipped each time (--skip-offsets avoids them on a re-run)",
            stats.stalls, image_name
        ));
    }

    // Synthetic EVTX files per provider, named as masstin's parsers expect. Validation
    // (a child process per file) is phase 2 of carve_image, so none happens here.
    let path_for = |provider: &str| -> PathBuf { temp_dir.join(provider_to_evtx_filename(provider)) };
    let written = groups.write_all(&path_for, &mut |_| true);
    let mut carved_evtx_files: Vec<String> = Vec::new();
    for w in written {
        if is_debug_mode() {
            eprintln!("[DEBUG] Synthetic EVTX: {} ({} chunks) -> {}", w.key, w.chunks_kept, w.path.display());
        }
        carved_evtx_files.push(w.path.to_string_lossy().to_string());
    }
    let troubled = stats.stalls > 0 || stats.read_errors > 0 || stats.aborted || hung > 0;
    Ok((chunks_found, orphan_records, carved_evtx_files, troubled))
}

/// Peek into a chunk to validate it and extract the provider name from the first record.
///
/// Migrated to evtx 0.11.2: the old `XmlOutput::with_writer` + `record.into_output()`
/// pattern was removed upstream. The new API exposes `record.into_xml()` which
/// consumes an `EvtxRecord` and returns `SerializedEvtxRecord<String>` with the
/// rendered XML in the public `.data` field.
enum Peek {
    Provider(String),
    Invalid,
    Hung,
}

/// `peek_chunk_provider` in its own thread with a 3-second budget. The
/// evtx crate can loop forever on malformed BinXML, which catch_unwind does
/// not stop; a hung thread is abandoned and the chunk reported.
fn peek_with_timeout(chunk: &[u8]) -> Peek {
    let data = chunk.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| peek_chunk_provider(&data)));
        let _ = tx.send(r);
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(Ok(Some(p))) => {
            let _ = handle.join();
            Peek::Provider(p)
        }
        Ok(_) => {
            let _ = handle.join();
            Peek::Invalid
        }
        Err(_) => {
            std::mem::forget(handle);
            Peek::Hung
        }
    }
}

fn peek_chunk_provider(chunk_data: &[u8]) -> Option<String> {
    // Validate chunk by trying to parse it
    let mut chunk_obj = evtx::EvtxChunkData::new(chunk_data.to_vec(), false).ok()?;

    let settings = std::sync::Arc::new(evtx::ParserSettings::default());
    let mut parsed = chunk_obj.parse(settings).ok()?;

    // Get provider from first record by rendering to XML
    for record_result in parsed.iter() {
        if let Ok(record) = record_result {
            if let Ok(serialized) = record.into_xml() {
                let xml = &serialized.data;
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
