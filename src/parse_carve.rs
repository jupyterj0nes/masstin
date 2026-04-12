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

use crate::parse::{is_debug_mode, LogData};

const ELFCHNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";
const EVTX_CHUNK_SIZE: usize = 65536; // 64KB
const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
const SCAN_BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4MB read blocks

/// Main entry point for carve-image action
pub fn carve_image(files: &[String], output: Option<&String>, unalloc_only: bool) {
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
            "e01" | "ex01" => carve_from_ewf(image_path, image_name, &temp_dir, unalloc_only),
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
        crate::banner::print_info("");
        crate::banner::print_info("  No EVTX chunks found in scanned images.");
        let _ = fs::remove_dir_all(&base_temp);
        return;
    }

    // Phase 2+3: Parse carved EVTX files through the existing masstin pipeline
    crate::banner::print_info("");
    crate::banner::print_info(&format!(
        "  {} synthetic EVTX files created from {} carved chunks",
        all_carved_evtx.len(), total_chunks
    ));

    let dirs: Vec<String> = vec![base_temp.to_string_lossy().to_string()];
    let empty_files: Vec<String> = vec![];
    crate::parse::parse_events_ex(&all_carved_evtx, &dirs, output, &[]);

    // Cleanup
    let _ = fs::remove_dir_all(&base_temp);

    crate::banner::print_info("");
    crate::banner::print_info(&format!(
        "  Carving summary: {} chunks, {} orphan records, completed in {:.2}s",
        total_chunks, total_orphans, start_time.elapsed().as_secs_f64()
    ));
}

// ─── Image format handlers ──────────────────────────────────────────────────

fn carve_from_raw(path: &str, name: &str, temp_dir: &Path, unalloc: bool) -> Result<(usize, usize, Vec<String>), String> {
    let file = File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut reader = BufReader::new(file);
    carve_from_seekable(&mut reader, size, name, temp_dir, unalloc)
}

fn carve_from_ewf(path: &str, name: &str, temp_dir: &Path, unalloc: bool) -> Result<(usize, usize, Vec<String>), String> {
    let ewf = ewf::EwfReader::open(path).map_err(|e| format!("Cannot open E01: {}", e))?;
    let size = ewf.total_size();
    let mut reader = BufReader::new(ewf);
    carve_from_seekable(&mut reader, size, name, temp_dir, unalloc)
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

    let total_blocks = image_size / SCAN_BLOCK_SIZE as u64 + 1;
    let pb = crate::banner::create_progress_bar(total_blocks);

    reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;

    let mut offset: u64 = 0;
    // Buffer with extra space for chunk boundary detection
    let mut buf = vec![0u8; SCAN_BLOCK_SIZE + EVTX_CHUNK_SIZE];
    let mut carry_over = 0usize;

    while offset < image_size {
        let to_read = SCAN_BLOCK_SIZE.min((image_size - offset) as usize);
        let bytes_read = match reader.read(&mut buf[carry_over..carry_over + to_read]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
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
                if let Some(provider) = peek_chunk_provider(&chunk_data) {
                    chunks_found += 1;
                    chunk_offsets.insert(chunk_abs_offset);

                    if is_debug_mode() {
                        eprintln!("[DEBUG] Chunk at {:#x}: provider={}", chunk_abs_offset, provider);
                    }

                    provider_chunks.entry(provider).or_default().push(chunk_data);
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
