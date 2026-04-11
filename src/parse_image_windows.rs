// -----------------------------------------------------------------------------
//  Forensic image parser for Windows EVTX
//  Opens E01/dd images or mounted volumes, parses NTFS, extracts EVTX files
//  (live + VSS) to temp dir, then delegates to the existing parse_events().
// -----------------------------------------------------------------------------

use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vshadow::VssVolume;
use crate::parse::{parse_events, is_debug_mode};
use crate::parse_linux::parse_linux;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const EVTX_LOGS_PATH: &[&str] = &["Windows", "System32", "winevt", "Logs"];
const UAL_SUM_PATH: &[&str] = &["Windows", "System32", "LogFiles", "Sum"];
const SCHTASKS_PATH: &[&str] = &["Windows", "System32", "Tasks"];

/// Result of extracting artifacts from a forensic image.
/// Contains separate directories for Windows (EVTX/UAL) and Linux logs.
struct ExtractedArtifacts {
    /// Directory containing extracted EVTX and UAL files (may be empty)
    evtx_dir: PathBuf,
    /// Directory containing extracted Linux log files, if any were found
    linux_logs_dir: Option<PathBuf>,
    /// Directory containing extracted Scheduled Task XML files, if any were found
    tasks_dir: Option<PathBuf>,
}

/// Main entry point: parse forensic disk images (Windows + Linux).
/// Auto-detects OS per partition: NTFS→EVTX+UAL+VSS, ext4→Linux logs.
/// All sources are extracted to temp directories first, then parsed together into a single CSV.
pub fn parse_image(files: &[String], directories: &[String], all_volumes: bool, output: Option<&String>, include_loose_artifacts: bool) {
    let start_time = std::time::Instant::now();

    // Collect all volume letters from directories and --all-volumes
    let mut volumes: Vec<String> = Vec::new();
    let mut real_dirs: Vec<String> = Vec::new();

    for d in directories {
        if is_drive_letter(d) {
            volumes.push(d.clone());
        } else {
            real_dirs.push(d.clone());
        }
    }

    if all_volumes {
        crate::banner::print_phase("1", "3", "Enumerating NTFS volumes on this system...");
        let system_volumes = enumerate_ntfs_volumes();
        if system_volumes.is_empty() {
            eprintln!("[WARNING] No NTFS volumes found. Are you running as Administrator?");
        } else {
            crate::banner::print_info(&format!("Found {} NTFS volume(s): {}",
                system_volumes.len(),
                system_volumes.join(", ")));
            for v in system_volumes {
                if !volumes.contains(&v) {
                    volumes.push(v);
                }
            }
        }
    }

    // Phase 1: Extract EVTX + UAL from all sources into temp directories
    let mut extracted_dirs: Vec<String> = Vec::new();
    let mut all_image_files: Vec<String> = files.to_vec();
    let base_temp = std::env::temp_dir().join("masstin_image_extract");
    let _ = fs::remove_dir_all(&base_temp); // Clean previous runs
    let _ = fs::create_dir_all(&base_temp);

    // Extract from mounted volumes: filesystem scan for live + raw I/O for VSS
    for vol in &volumes {
        crate::banner::print_phase("1", "3", &format!("Opening mounted volume {}...", vol));
        crate::banner::print_info(&format!("Detected {} as a mounted volume — will extract EVTX + UAL from filesystem and VSS from raw volume", vol));

        let volume_label = vol.trim_end_matches(&['\\', '/'][..]).to_string();

        // 1. Add the mounted path directly for filesystem scanning (EVTX + UAL)
        //    This works reliably on mounted drives, just like parse-windows -d
        //    Note: pass without trailing \ so parse_events doesn't show the VSS tip
        extracted_dirs.push(volume_label.clone());
        crate::banner::print_info("  Live volume: scanning filesystem for EVTX + UAL...");

        // 2. Open raw volume for VSS extraction only
        crate::banner::print_info("  VSS: opening raw volume for shadow copy recovery...");
        let temp_dir = base_temp.join(format!("vol_{}", volume_label));
        let _ = fs::create_dir_all(&temp_dir);

        match extract_vss_only_from_volume(&volume_label, &temp_dir) {
            Ok(Some(dir)) => {
                let dir_str = dir.to_string_lossy().to_string();
                crate::banner::print_phase_result("VSS EVTX extracted from volume");
                extracted_dirs.push(dir_str);
            }
            Ok(None) => {
                crate::banner::print_info("  No VSS stores found or no EVTX in VSS");
            }
            Err(e) => {
                crate::banner::print_info(&format!("  VSS extraction failed: {}", e));
            }
        }
    }

    // Scan real directories for forensic images (E01, VMDK, dd, raw)
    if !real_dirs.is_empty() {
        let image_extensions = ["e01", "ex01", "vmdk", "dd", "raw", "img", "001"];
        let mut discovered: Vec<String> = Vec::new();

        let sp = crate::banner::create_spinner("Scanning for forensic images...");
        let mut dirs_scanned: usize = 0;
        for dir in &real_dirs {
            scan_for_images(Path::new(dir), &image_extensions, &mut discovered, 0, &sp, &mut dirs_scanned);
        }
        sp.finish_and_clear();

        if !discovered.is_empty() {
            // Deduplicate: for E01 split files, only keep the .E01 (not .E02, .E03...)
            // For VMDK split, only keep the descriptor (not -s001, -s002...)
            let filtered: Vec<String> = discovered.into_iter().filter(|p| {
                let name = Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or("");
                let lower = name.to_lowercase();
                // Skip E01 segment files (.e02, .e03, etc.)
                if lower.ends_with(".e01") || lower.ends_with(".ex01") { return true; }
                // Skip VMDK split extents, snapshots, and flat data files — only keep base descriptors
                if lower.ends_with(".vmdk") {
                    let stem = Path::new(p).file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    let stem_lower = stem.to_lowercase();
                    // Skip flat data files: name-flat.vmdk
                    if stem_lower.ends_with("-flat") { return false; }
                    // Skip change tracking block files: name-ctk.vmdk
                    if stem_lower.ends_with("-ctk") { return false; }
                    // Skip split extents: name-sNNN.vmdk
                    if let Some(pos) = stem.rfind("-s") {
                        let after = &stem[pos + 2..];
                        if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
                            return false;
                        }
                    }
                    // Skip VMware snapshots: name-NNNNNN.vmdk
                    if let Some(pos) = stem.rfind("-0") {
                        let after = &stem[pos + 1..];
                        if after.len() >= 6 && after[..6].chars().all(|c| c.is_ascii_digit()) {
                            return false;
                        }
                    }
                    return true;
                }
                // For dd/raw/img, keep all
                true
            }).collect();

            crate::banner::print_phase_result(&format!(
                "{} forensic image(s) found in scanned directories", filtered.len()
            ));

            // List images numbered
            for (i, img) in filtered.iter().enumerate() {
                let name = Path::new(img).file_name().and_then(|n| n.to_str()).unwrap_or(img);
                crate::banner::print_info(&format!("  [{}] {}", i + 1, name));
            }

            // Add discovered images to the processing list
            all_image_files.extend(filtered);
        }
    }

    let total_images = all_image_files.len();

    // Extract from image files — use image name as temp subdirectory
    let mut linux_log_dirs: Vec<String> = Vec::new();
    let mut task_dirs: Vec<(String, String)> = Vec::new(); // (dir, hostname)

    let mut images_processed = 0;
    let mut images_skipped = 0;

    for (img_idx, image_path) in all_image_files.iter().enumerate() {
        let ext = Path::new(image_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let image_name = Path::new(image_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(image_path)
            .to_string();

        let file_size_str = fs::metadata(image_path)
            .map(|m| {
                let gb = m.len() as f64 / 1_073_741_824.0;
                if gb >= 1.0 { format!("{:.1} GB", gb) }
                else { format!("{:.0} MB", m.len() as f64 / 1_048_576.0) }
            })
            .unwrap_or_else(|_| "? size".to_string());

        crate::banner::print_info("");
        crate::banner::print_phase_result(&format!(
            "Image {}/{}: {} ({}, {})", img_idx + 1, total_images, image_name, ext.to_uppercase(), file_size_str
        ));
        crate::banner::print_info(&format!("  {}", image_path));

        let temp_dir = base_temp.join(format!("{}_{}", img_idx, image_name));
        let _ = fs::create_dir_all(&temp_dir);

        let result = match ext.as_str() {
            "e01" | "ex01" => extract_evtx_from_image_ewf(image_path, &temp_dir),
            "vmdk" => extract_evtx_from_image_vmdk(image_path, &temp_dir),
            "dd" | "raw" | "img" | "001" => extract_evtx_from_image_raw(image_path, &temp_dir),
            _ => extract_evtx_from_image_raw(image_path, &temp_dir)
                    .or_else(|_| extract_evtx_from_image_ewf(image_path, &temp_dir)),
        };

        match result {
            Ok(artifacts) => {
                images_processed += 1;
                // Only add EVTX dir if it actually contains extracted files
                if artifacts.evtx_dir.exists() && fs::read_dir(&artifacts.evtx_dir).map(|mut d| d.next().is_some()).unwrap_or(false) {
                    extracted_dirs.push(artifacts.evtx_dir.to_string_lossy().to_string());
                }
                if let Some(linux_dir) = artifacts.linux_logs_dir {
                    linux_log_dirs.push(linux_dir.to_string_lossy().to_string());
                }
                if let Some(tdir) = artifacts.tasks_dir {
                    let hostname = extract_hostname_from_evtx_dir(&artifacts.evtx_dir);
                    task_dirs.push((tdir.to_string_lossy().to_string(), hostname));
                }
            }
            Err(e) => {
                images_skipped += 1;
                let msg = e.to_string();
                if msg.contains("Incomplete VMDK") {
                    // Extract the missing flat extent filename from the error
                    let detail = if let Some(pos) = msg.find("flat extent '") {
                        let after = &msg[pos + 13..];
                        if let Some(end) = after.find('\'') {
                            format!(" (needs: {})", &after[..end])
                        } else { String::new() }
                    } else { String::new() };
                    crate::banner::print_info(&format!("  Skipped: VMDK descriptor without data file{}", detail));
                } else if msg.contains("not yet supported") {
                    crate::banner::print_info(&format!("  Skipped: {}", msg));
                } else if msg.contains("Empty image (0 bytes)") {
                    crate::banner::print_info(&format!("  Skipped: empty image (0 bytes, VMFS thin disk — data not in support bundle)"));
                } else if msg.contains("No NTFS or ext4") || msg.contains("No partitions found") {
                    crate::banner::print_info(&format!("  Skipped: {}", msg));
                } else if msg.contains("but no forensic artifacts") {
                    crate::banner::print_info(&format!("  Skipped: {}", msg));
                } else {
                    crate::banner::print_info(&format!("  Error: {}", msg));
                }
            }
        }
    }

    // Add real directories for loose EVTX/log files (only in massive mode)
    if include_loose_artifacts {
        for d in &real_dirs {
            extracted_dirs.push(d.clone());
        }
    }

    // Parse Scheduled Tasks for remote activity (silent — only shows if found)
    let mut all_task_events = Vec::new();
    if !task_dirs.is_empty() {
        for (tdir, hostname) in &task_dirs {
            let dirs_vec = vec![tdir.clone()];
            let events = crate::parse_tasks::parse_scheduled_tasks(&dirs_vec, hostname);
            all_task_events.extend(events);
        }
    }

    if extracted_dirs.is_empty() && linux_log_dirs.is_empty() && all_task_events.is_empty() {
        eprintln!("[ERROR] No artifacts extracted from any source.");
        return;
    }

    // Phase 2+3: Parse extracted directories and generate output CSV
    let empty_files: Vec<String> = vec![];
    let has_windows = !extracted_dirs.is_empty();
    let has_linux = !linux_log_dirs.is_empty();

    if has_windows && has_linux {
        // Both OS types found — parse each separately, then merge into one CSV
        let win_tmp = base_temp.join("_windows_output.csv");
        let linux_tmp = base_temp.join("_linux_output.csv");
        let win_tmp_str = win_tmp.to_string_lossy().to_string();
        let linux_tmp_str = linux_tmp.to_string_lossy().to_string();

        crate::banner::print_info("Parsing Windows artifacts (EVTX + UAL)...");
        parse_events(&empty_files, &extracted_dirs, Some(&win_tmp_str));

        crate::banner::print_info("Parsing Linux artifacts (auth.log, wtmp, etc.)...");
        parse_linux(&empty_files, &linux_log_dirs, Some(&linux_tmp_str));

        // Rewrite log_filename paths before merging
        rewrite_log_filenames(&win_tmp_str);
        crate::parse_image_linux::rewrite_log_filenames_linux(&linux_tmp_str);

        // Merge both CSVs into the final output (deduplicated, sorted by time_created)
        crate::banner::print_info("Merging Windows + Linux timelines...");
        let merge_files_list = vec![win_tmp_str.clone(), linux_tmp_str.clone()];
        match crate::merge::merge_files(&merge_files_list, output) {
            Ok(()) => {
                crate::banner::print_phase_result("Merged Windows + Linux timeline generated");
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to merge timelines: {}", e);
            }
        }
    } else if has_windows {
        // Windows only
        parse_events(&empty_files, &extracted_dirs, output);
        if let Some(out_path) = output {
            rewrite_log_filenames(out_path);
        }
    } else {
        // Linux only
        parse_linux(&empty_files, &linux_log_dirs, output);
        if let Some(out_path) = output {
            crate::parse_image_linux::rewrite_log_filenames_linux(out_path);
        }
    }

    // Append task events to the output CSV (after main parsing)
    if !all_task_events.is_empty() {
        if let Some(out_path) = output {
            append_logdata_to_csv(out_path, &all_task_events);
        }
    }

    // Suggest graph database loading
    if let Some(out_path) = output {
        crate::banner::print_info("");
        crate::banner::print_info(&format!("Load into graph: masstin -a load-memgraph -f {} --database localhost:7687", out_path));
    }

    // Cleanup temp directories
    let _ = fs::remove_dir_all(&base_temp);
}

/// Extract hostname from extracted EVTX files by reading the Computer field from the first record.
fn extract_hostname_from_evtx_dir(evtx_dir: &Path) -> String {
    // Find Security.evtx or any .evtx in the extracted directory
    let candidates = ["Security.evtx", "System.evtx"];
    for candidate in &candidates {
        // Search recursively in partition subdirectories
        if let Ok(entries) = fs::read_dir(evtx_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let evtx_path = path.join(candidate);
                    if evtx_path.exists() {
                        if let Some(hostname) = read_hostname_from_evtx(&evtx_path) {
                            return hostname;
                        }
                    }
                }
            }
        }
    }
    String::new()
}

/// Read the Computer field from the first record of an EVTX file.
fn read_hostname_from_evtx(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).ok()?;
    let cursor = std::io::Cursor::new(data);
    let mut parser = evtx::EvtxParser::from_read_seek(cursor).ok()?;
    for record in parser.records() {
        if let Ok(r) = record {
            let xml = r.data;
            // Quick extraction of <Computer> from XML
            if let Some(start) = xml.find("<Computer>") {
                let start = start + "<Computer>".len();
                if let Some(end) = xml[start..].find("</Computer>") {
                    let hostname = xml[start..start + end].trim().to_string();
                    if !hostname.is_empty() {
                        return Some(hostname);
                    }
                }
            }
        }
    }
    None
}

/// Extract the most common computer name from an existing CSV (dst_computer column).
fn extract_computer_from_csv(csv_path: &str) -> Option<String> {
    let content = fs::read_to_string(csv_path).ok()?;
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, line) in content.lines().enumerate() {
        if i == 0 { continue; } // skip header
        let fields: Vec<&str> = line.splitn(3, ',').collect();
        if fields.len() >= 2 && !fields[1].is_empty() {
            *counts.entry(fields[1].to_string()).or_insert(0) += 1;
        }
        if i > 100 { break; } // sample first 100 lines
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(name, _)| name.trim_start_matches('\\').to_string())
}

/// Append LogData events to an existing CSV file.
fn append_logdata_to_csv(csv_path: &str, events: &[crate::parse::LogData]) {
    use std::io::Write;
    let mut file = match fs::OpenOptions::new().append(true).open(csv_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    for e in events {
        let line = format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            e.time_created, e.computer, e.event_type, e.event_id,
            e.logon_type, e.target_user_name, e.target_domain_name,
            e.workstation_name, e.ip_address,
            e.subject_user_name, e.subject_domain_name,
            e.logon_id, e.detail, e.filename);
        let _ = file.write_all(line.as_bytes());
    }
}

// -----------------------------------------------------------------------------
//  Drive letter detection and volume enumeration
// -----------------------------------------------------------------------------

/// Recursively scan a directory for forensic image files.
fn scan_for_images(dir: &Path, extensions: &[&str], results: &mut Vec<String>, depth: usize, spinner: &indicatif::ProgressBar, dirs_scanned: &mut usize) {
    if depth > 10 { return; }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    *dirs_scanned += 1;
    spinner.set_message(format!("{} dirs scanned, {} images found", dirs_scanned, results.len()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('$') || name.starts_with('.') || name == "System Volume Information" {
                continue;
            }
            scan_for_images(&path, extensions, results, depth + 1, spinner, dirs_scanned);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.iter().any(|x| x.eq_ignore_ascii_case(ext)) {
                    results.push(path.to_string_lossy().to_string());
                    spinner.set_message(format!("{} dirs scanned, {} images found", dirs_scanned, results.len()));
                }
            }
        }
    }
}

/// Describe partition types found in an image (for error messages when NTFS/ext4 not found)
fn describe_partitions<R: Read + Seek>(reader: &mut R, _image_size: u64) -> String {
    let mut types = Vec::new();
    if reader.seek(SeekFrom::Start(0)).is_err() { return String::new(); }
    let mut mbr_buf = [0u8; 512];
    if reader.read_exact(&mut mbr_buf).is_err() || mbr_buf[510] != 0x55 || mbr_buf[511] != 0xAA {
        return String::new();
    }
    let part0_type = mbr_buf[446 + 4];
    if part0_type == 0xEE {
        // Try to read GPT partition types
        if reader.seek(SeekFrom::Start(512)).is_ok() {
            let mut gpt_header = [0u8; 92];
            if reader.read_exact(&mut gpt_header).is_ok() && &gpt_header[0..8] == b"EFI PART" {
                let entry_start_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
                let entry_count = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap());
                let entry_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap());
                let mut gpt_types = Vec::new();
                for i in 0..entry_count.min(16) {
                    let off = entry_start_lba * 512 + (i as u64 * entry_size as u64);
                    if reader.seek(SeekFrom::Start(off)).is_err() { break; }
                    let mut entry = vec![0u8; entry_size as usize];
                    if reader.read_exact(&mut entry).is_err() { break; }
                    let guid: [u8; 16] = entry[0..16].try_into().unwrap();
                    if guid == [0u8; 16] { continue; }
                    let name = match guid {
                        [0x28, 0x73, 0x2A, 0xC1, ..] => "EFI System",
                        [0x16, 0xE3, 0xC9, 0xE3, ..] => "MS Reserved",
                        [0xA2, 0xA0, 0xD0, 0xEB, ..] => "Basic Data (NTFS/FAT)",
                        [0xAA, 0xC8, 0x08, 0x58, ..] => "LDM Metadata",
                        [0xAF, 0x3D, 0xC6, 0x0F, ..] => "Linux filesystem",
                        [0x79, 0xD3, 0xD6, 0xE6, ..] => "Linux LVM",
                        [0x0F, 0xC6, 0x3D, 0xAF, ..] => "Linux filesystem",
                        _ => "Unknown GPT type",
                    };
                    gpt_types.push(name.to_string());
                }
                if gpt_types.is_empty() {
                    types.push("GPT disk (no partitions)".to_string());
                } else {
                    types.push(format!("GPT: {}", gpt_types.join(", ")));
                }
            } else {
                types.push("GPT disk (header unreadable)".to_string());
            }
        } else {
            types.push("GPT disk".to_string());
        }
    } else {
        for i in 0..4 {
            let entry_offset = 446 + i * 16;
            let part_type = mbr_buf[entry_offset + 4];
            if part_type != 0 {
                let name = match part_type {
                    0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => "FAT",
                    0x05 | 0x0F | 0x85 => "Extended",
                    0x07 => "NTFS/exFAT",
                    0x0A => "OS/2 Boot",
                    0x11 | 0x14 | 0x16 | 0x1B | 0x1C | 0x1E => "Hidden FAT",
                    0x27 => "Recovery",
                    0x42 => "Dynamic/LDM",
                    0x82 => "Linux swap",
                    0x83 => "Linux",
                    0x8E => "Linux LVM",
                    0xA5 => "FreeBSD",
                    0xEE => "GPT protective",
                    0xFD => "Linux RAID",
                    _ => "Unknown",
                };
                types.push(format!("MBR type 0x{:02X} ({})", part_type, name));
            }
        }
    }
    types.join(", ")
}

/// Check if a string is a Windows drive letter (e.g. "D:", "D:\", "E:")
fn is_drive_letter(s: &str) -> bool {
    let trimmed = s.trim_end_matches(&['\\', '/'][..]);
    trimmed.len() == 2
        && trimmed.as_bytes()[0].is_ascii_alphabetic()
        && trimmed.as_bytes()[1] == b':'
}

/// Enumerate all NTFS volumes on the system (Windows only)
fn enumerate_ntfs_volumes() -> Vec<String> {
    let mut volumes = Vec::new();

    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let root = format!("{}\\", drive);
            let root_wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();

            extern "system" {
                fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
            }

            let drive_type = unsafe { GetDriveTypeW(root_wide.as_ptr()) };
            // DRIVE_FIXED = 3, DRIVE_REMOVABLE = 2, DRIVE_REMOTE = 4
            if drive_type == 3 || drive_type == 2 {
                // Check if we can open it and if it's NTFS
                let device = format!("\\\\.\\{}", drive);
                if let Ok(fh) = File::open(&device) {
                    let size = get_device_size_ioctl(&fh);
                    if size > 0 {
                        // Try to verify NTFS signature
                        let mut sr = SectorReader::new(fh, 512, size);
                        let mut sig = [0u8; 8];
                        if sr.seek(SeekFrom::Start(3)).is_ok()
                            && sr.read_exact(&mut sig).is_ok()
                            && &sig == NTFS_SIGNATURE
                        {
                            volumes.push(drive);
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        // On Linux, check /proc/mounts for NTFS partitions
        if let Ok(content) = fs::read_to_string("/proc/mounts") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[2].contains("ntfs") && parts[0].starts_with("/dev/") {
                    volumes.push(parts[0].to_string());
                }
            }
        }
    }

    volumes
}

// -----------------------------------------------------------------------------
//  Sector-aligned reader for raw device I/O (required on Windows)
// -----------------------------------------------------------------------------

struct SectorReader {
    inner: File,
    sector_size: usize,
    cache: Vec<u8>,
    cache_start: u64,
    cache_len: usize,
    pos: u64,
    size: u64,
}

impl SectorReader {
    fn new(inner: File, sector_size: usize, size: u64) -> Self {
        Self {
            inner,
            sector_size,
            cache: vec![0u8; sector_size * 128], // 64 KB cache
            cache_start: u64::MAX,
            cache_len: 0,
            pos: 0,
            size,
        }
    }

    fn fill_cache(&mut self, offset: u64) -> std::io::Result<()> {
        let aligned = (offset / self.sector_size as u64) * self.sector_size as u64;
        if self.cache_start != u64::MAX
            && aligned >= self.cache_start
            && aligned < self.cache_start + self.cache_len as u64
        {
            return Ok(());
        }
        self.inner.seek(SeekFrom::Start(aligned))?;
        self.cache_len = self.inner.read(&mut self.cache)?;
        self.cache_start = aligned;
        Ok(())
    }
}

impl Read for SectorReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.size > 0 && self.pos >= self.size {
            return Ok(0);
        }
        let mut total = 0;
        while total < buf.len() {
            self.fill_cache(self.pos)?;
            if self.cache_start == u64::MAX || self.cache_len == 0 { break; }
            let offset_in_cache = (self.pos - self.cache_start) as usize;
            if offset_in_cache >= self.cache_len { break; }
            let available = self.cache_len - offset_in_cache;
            let to_copy = (buf.len() - total).min(available);
            buf[total..total + to_copy]
                .copy_from_slice(&self.cache[offset_in_cache..offset_in_cache + to_copy]);
            self.pos += to_copy as u64;
            total += to_copy;
        }
        Ok(total)
    }
}

impl Seek for SectorReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if self.size > 0 {
                    (self.size as i64 + n) as u64
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported, "cannot seek from end: device size unknown"));
                }
            }
            SeekFrom::Current(n) => (self.pos as i64 + n) as u64,
        };
        Ok(self.pos)
    }
}

#[cfg(windows)]
fn get_device_size_ioctl(file: &File) -> u64 {
    use std::os::windows::io::AsRawHandle;
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405C;
    extern "system" {
        fn DeviceIoControl(
            hDevice: isize, dwIoControlCode: u32,
            lpInBuffer: *const u8, nInBufferSize: u32,
            lpOutBuffer: *mut u8, nOutBufferSize: u32,
            lpBytesReturned: *mut u32, lpOverlapped: *const u8,
        ) -> i32;
    }
    let mut length: i64 = 0;
    let mut returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as isize, IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(), 0,
            &mut length as *mut i64 as *mut u8, std::mem::size_of::<i64>() as u32,
            &mut returned, std::ptr::null(),
        )
    };
    if result != 0 && length > 0 { length as u64 } else { 0 }
}

#[cfg(not(windows))]
fn get_device_size_ioctl(_file: &File) -> u64 { 0 }

// -----------------------------------------------------------------------------
//  Extract EVTX from a mounted volume (live + VSS)
// -----------------------------------------------------------------------------

/// Extract EVTX only from VSS stores on a mounted volume (raw I/O).
/// Returns the output directory if any EVTX were found, None if no VSS or no EVTX.
fn extract_vss_only_from_volume(drive: &str, temp_dir: &Path) -> Result<Option<PathBuf>, String> {
    let device_path = if drive.starts_with("\\\\.\\") {
        drive.to_string()
    } else {
        format!("\\\\.\\{}", drive)
    };

    let fh = File::open(&device_path)
        .map_err(|e| format!("Cannot open volume {} — are you running as Administrator? ({})", device_path, e))?;

    let size = get_device_size_ioctl(&fh);
    if size == 0 {
        return Err(format!("Cannot read volume size for {}. Run as Administrator.", device_path));
    }

    crate::banner::print_info(&format!("    Volume size: {:.2} GB", size as f64 / 1_073_741_824.0));

    let mut reader = BufReader::new(SectorReader::new(fh, 512, size));

    if !verify_ntfs_signature(&mut reader, 0) {
        return Ok(None);
    }

    let evtx_output_dir = temp_dir.join("vss_extracted");
    let _ = fs::create_dir_all(&evtx_output_dir);
    let mut total_evtx = 0;

    match VssVolume::new(&mut reader) {
        Ok(vss) if vss.store_count() > 0 => {
            crate::banner::print_phase_result(&format!(
                "    {} VSS store(s) detected!", vss.store_count()
            ));

            for s in 0..vss.store_count() {
                if let Ok(info) = vss.store_info(s) {
                    crate::banner::print_info(&format!(
                        "    VSS store {}: created {}", s, info.creation_time_utc()
                    ));
                }
                if let Ok((blocks, bytes)) = vss.store_delta_size(&mut reader, s) {
                    crate::banner::print_info(&format!(
                        "      {} changed blocks ({:.1} MB delta)", blocks, bytes as f64 / 1_048_576.0
                    ));
                }

                crate::banner::print_info(&format!("    Extracting EVTX from VSS store {}...", s));
                match vss.store_reader(&mut reader, s) {
                    Ok(mut store_reader) => {
                        match extract_evtx_from_vss_store(&mut store_reader, &evtx_output_dir, 0, s) {
                            Ok(count) => {
                                total_evtx += count;
                                crate::banner::print_info(&format!(
                                    "      {} EVTX files extracted from VSS store {}", count, s
                                ));
                            }
                            Err(e) => {
                                if is_debug_mode() {
                                    eprintln!("[DEBUG] VSS store {} error: {}", s, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if is_debug_mode() {
                            eprintln!("[DEBUG] Cannot open VSS store {}: {}", s, e);
                        }
                    }
                }
            }
        }
        Ok(_) => {
            crate::banner::print_info("    No Volume Shadow Copy stores found");
        }
        Err(_) => {
            crate::banner::print_info("    No Volume Shadow Copy stores found");
        }
    }

    if total_evtx > 0 {
        Ok(Some(evtx_output_dir))
    } else {
        Ok(None)
    }
}

fn extract_evtx_from_volume(drive: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let device_path = if drive.starts_with("\\\\.\\") {
        drive.to_string()
    } else {
        format!("\\\\.\\{}", drive)
    };

    crate::banner::print_info(&format!("Opening raw volume: {}", device_path));

    let fh = File::open(&device_path)
        .map_err(|e| format!("Cannot open volume {} — are you running as Administrator? ({})", device_path, e))?;

    let size = get_device_size_ioctl(&fh);
    if size == 0 {
        return Err(format!("Cannot read volume size for {}. Run as Administrator.", device_path));
    }

    crate::banner::print_info(&format!("Volume size: {:.2} GB", size as f64 / 1_073_741_824.0));

    let mut reader = BufReader::new(SectorReader::new(fh, 512, size));

    // Verify NTFS
    if !verify_ntfs_signature(&mut reader, 0) {
        return Err(format!("Volume {} is not NTFS", drive));
    }

    crate::banner::print_info("NTFS filesystem confirmed");

    let evtx_output_dir = temp_dir.join("evtx_extracted");
    let _ = fs::create_dir_all(&evtx_output_dir);
    let mut total_evtx = 0;

    // 1. Extract EVTX from live volume (offset 0 = start of partition)
    crate::banner::print_info("Extracting EVTX from live volume...");
    match extract_evtx_from_ntfs_partition(&mut reader, 0, &evtx_output_dir, 0) {
        Ok(count) => {
            total_evtx += count;
            crate::banner::print_phase_result(&format!("{} EVTX files extracted from live volume", count));
        }
        Err(e) => {
            crate::banner::print_info(&format!("Warning: could not extract from live volume: {}", e));
        }
    }

    // 1b. Extract UAL databases from live volume
    let ual_dir = evtx_output_dir.join("partition_0").join("Sum");
    match extract_files_from_ntfs_path(&mut reader, 0, UAL_SUM_PATH, "mdb", &ual_dir) {
        Ok(count) if count > 0 => {
            crate::banner::print_info(&format!("  {} UAL database files extracted from live volume", count));
        }
        _ => {}
    }

    // 2. Check for VSS stores and extract from each
    crate::banner::print_info("Checking for Volume Shadow Copy stores...");
    match VssVolume::new(&mut reader) {
        Ok(vss) if vss.store_count() > 0 => {
            crate::banner::print_phase_result(&format!(
                "{} VSS store(s) detected!", vss.store_count()
            ));

            for s in 0..vss.store_count() {
                if let Ok(info) = vss.store_info(s) {
                    crate::banner::print_info(&format!(
                        "  VSS store {}: created {}", s, info.creation_time_utc()
                    ));
                }
                if let Ok((blocks, bytes)) = vss.store_delta_size(&mut reader, s) {
                    crate::banner::print_info(&format!(
                        "    {} changed blocks ({:.1} MB delta)", blocks, bytes as f64 / 1_048_576.0
                    ));
                }

                crate::banner::print_info(&format!("  Extracting EVTX from VSS store {}...", s));
                match vss.store_reader(&mut reader, s) {
                    Ok(mut store_reader) => {
                        match extract_evtx_from_vss_store(&mut store_reader, &evtx_output_dir, 0, s) {
                            Ok(count) => {
                                total_evtx += count;
                                crate::banner::print_info(&format!(
                                    "    {} EVTX files extracted from VSS store {}", count, s
                                ));
                            }
                            Err(e) => {
                                if is_debug_mode() {
                                    eprintln!("[DEBUG] VSS store {} error: {}", s, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if is_debug_mode() {
                            eprintln!("[DEBUG] Cannot open VSS store {}: {}", s, e);
                        }
                    }
                }
            }
        }
        Ok(_) => {
            crate::banner::print_info("No Volume Shadow Copy stores found on this volume");
        }
        Err(_) => {
            crate::banner::print_info("No Volume Shadow Copy stores found on this volume");
        }
    }

    if total_evtx == 0 {
        return Err(format!("No EVTX files found on volume {}", drive));
    }

    crate::banner::print_phase_result(&format!("{} EVTX files extracted total from volume {}", total_evtx, drive));
    Ok(evtx_output_dir)
}

/// Extract EVTX from an E01 image
fn extract_evtx_from_image_ewf(image_path: &str, temp_dir: &Path) -> Result<ExtractedArtifacts, String> {
    let reader = ewf::EwfReader::open(image_path)
        .map_err(|e| format!("Cannot open E01: {}", e))?;

    let image_size = reader.total_size();
    if is_debug_mode() {
        eprintln!("[DEBUG] Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0);
    }

    let mut buf_reader = BufReader::new(reader);
    extract_evtx_from_seekable(&mut buf_reader, image_size, temp_dir)
}

/// Extract EVTX from a VMDK image
fn extract_evtx_from_image_vmdk(image_path: &str, temp_dir: &Path) -> Result<ExtractedArtifacts, String> {
    let reader = crate::vmdk::VmdkReader::open(image_path)
        .map_err(|e| format!("Cannot open VMDK: {}", e))?;

    let image_size = reader.total_size();
    if is_debug_mode() {
        eprintln!("[DEBUG] Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0);
    }

    let mut buf_reader = BufReader::new(reader);
    extract_evtx_from_seekable(&mut buf_reader, image_size, temp_dir)
}

/// Extract EVTX from a raw/dd image
fn extract_evtx_from_image_raw(image_path: &str, temp_dir: &Path) -> Result<ExtractedArtifacts, String> {
    let file = File::open(image_path)
        .map_err(|e| format!("Cannot open raw image: {}", e))?;

    let image_size = file.metadata()
        .map_err(|e| format!("Cannot read file size: {}", e))?
        .len();

    if is_debug_mode() {
        eprintln!("[DEBUG] Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0);
    }

    let mut buf_reader = BufReader::new(file);
    extract_evtx_from_seekable(&mut buf_reader, image_size, temp_dir)
}

/// Core logic: find all partitions (NTFS + ext4) and extract forensic artifacts
fn extract_evtx_from_seekable<R: Read + Seek + 'static>(
    reader: &mut R,
    image_size: u64,
    temp_dir: &Path,
) -> Result<ExtractedArtifacts, String> {
    if image_size == 0 {
        return Err("Empty image (0 bytes) — VMFS thin disk data not available".to_string());
    }

    // Find NTFS partition offsets
    let ntfs_partitions = find_ntfs_partitions(reader, image_size).unwrap_or_default();
    // Find ext4 partition offsets
    let ext4_partitions = crate::parse_image_linux::find_linux_partitions_public(reader, image_size).unwrap_or_default();

    if ntfs_partitions.is_empty() && ext4_partitions.is_empty() {
        // Try to report what partition types exist for debugging
        let part_info = describe_partitions(reader, image_size);
        if part_info.is_empty() {
            return Err("No partitions found (no MBR/GPT detected)".to_string());
        }
        return Err(format!("No NTFS or ext4 found. Detected: {}", part_info));
    }

    let partitions = &ntfs_partitions;

    let evtx_output_dir = temp_dir.join("evtx_extracted");
    let _ = fs::create_dir_all(&evtx_output_dir);
    let mut total_evtx = 0;
    let tasks_dir = temp_dir.join("tasks_extracted");
    let mut total_tasks = 0;
    let mut total_ual = 0;
    let mut total_vss = 0;

    for (i, partition_offset) in partitions.iter().enumerate() {
        if is_debug_mode() {
            eprintln!("[DEBUG] Partition {} at offset {:#x} ({:.2} GB)",
                i + 1, partition_offset, *partition_offset as f64 / 1_073_741_824.0);
        }

        // Extract EVTX from the live (current) volume
        match extract_evtx_from_ntfs_partition(reader, *partition_offset, &evtx_output_dir, i) {
            Ok(count) => {
                total_evtx += count;
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Partition {} error: {}", i + 1, e);
                }
            }
        }

        // Extract UAL databases from live volume
        let ual_dir = evtx_output_dir.join(format!("partition_{}", i)).join("Sum");
        if let Ok(count) = extract_files_from_ntfs_path(reader, *partition_offset, UAL_SUM_PATH, "mdb", &ual_dir) {
            total_ual += count;
        }

        // Extract Scheduled Task XML files from live volume
        let tasks_part_dir = tasks_dir.join(format!("partition_{}", i));
        if let Ok(count) = extract_all_files_from_ntfs_path(reader, *partition_offset, SCHTASKS_PATH, &tasks_part_dir) {
            total_tasks += count;
        }

        // Check for Volume Shadow Copies (VSS) and extract EVTX from each
        let mut offset_reader = OffsetReader::new(reader, *partition_offset);
        match VssVolume::new(&mut offset_reader) {
            Ok(vss) if vss.store_count() > 0 => {
                for s in 0..vss.store_count() {
                    total_vss += 1;
                    if is_debug_mode() {
                        if let Ok((blocks, bytes)) = vss.store_delta_size(&mut offset_reader, s) {
                            eprintln!("[DEBUG] VSS store {}: {} changed blocks ({:.1} MB delta)",
                                s, blocks, bytes as f64 / 1_048_576.0);
                        }
                    }

                    match vss.store_reader(&mut offset_reader, s) {
                        Ok(mut store_reader) => {
                            match extract_evtx_from_vss_store(&mut store_reader, &evtx_output_dir, i, s) {
                                Ok(count) => {
                                    total_evtx += count;
                                }
                                Err(e) => {
                                    if is_debug_mode() {
                                        eprintln!("[DEBUG] VSS store {} error: {}", s, e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if is_debug_mode() {
                                eprintln!("[DEBUG] Cannot open VSS store {}: {}", s, e);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Compact summary line
    let mut parts = Vec::new();
    parts.push(format!("{} NTFS", ntfs_partitions.len()));
    if total_vss > 0 { parts.push(format!("{} VSS", total_vss)); }
    if !ext4_partitions.is_empty() { parts.push(format!("{} ext4", ext4_partitions.len())); }
    crate::banner::print_info(&format!("  Partitions: {}", parts.join(", ")));

    let mut artifact_parts = Vec::new();
    if total_evtx > 0 { artifact_parts.push(format!("{} EVTX", total_evtx)); }
    if total_ual > 0 { artifact_parts.push(format!("{} UAL", total_ual)); }
    if total_tasks > 0 { artifact_parts.push(format!("{} Tasks", total_tasks)); }
    if !artifact_parts.is_empty() {
        crate::banner::print_info(&format!("  Extracted: {}", artifact_parts.join(" + ")));
    }

    // Now process ext4 partitions (Linux)
    let mut total_linux_logs = 0;
    let linux_logs_dir = temp_dir.join("linux_logs_extracted");

    for (i, partition_offset) in ext4_partitions.iter().enumerate() {
        if is_debug_mode() {
            eprintln!("[DEBUG] ext4 partition {} at offset {:#x} ({:.2} GB)",
                i + 1, partition_offset, *partition_offset as f64 / 1_073_741_824.0);
        }

        match crate::parse_image_linux::extract_linux_logs_from_ext4(reader, *partition_offset, &linux_logs_dir, i) {
            Ok(count) if count > 0 => {
                total_linux_logs += count;
                crate::banner::print_info(&format!("  {} Linux log files extracted from ext4 partition {}", count, i));
            }
            Ok(_) => {
                crate::banner::print_info(&format!("  ext4 partition {}: no log files found (auth.log, wtmp, etc.)", i));
            }
            Err(e) => {
                crate::banner::print_info(&format!("  ext4 partition {}: {}", i, e));
            }
        }
    }

    if total_linux_logs > 0 {
        crate::banner::print_phase_result(&format!("{} Linux log files extracted total", total_linux_logs));
    }

    if total_evtx == 0 && total_linux_logs == 0 && total_tasks == 0 {
        let mut found = Vec::new();
        if !ntfs_partitions.is_empty() { found.push(format!("{} NTFS", ntfs_partitions.len())); }
        if !ext4_partitions.is_empty() { found.push(format!("{} ext4", ext4_partitions.len())); }
        if found.is_empty() {
            return Err("No NTFS or ext4 partitions found".to_string());
        }
        return Err(format!("Partitions found ({}) but no forensic artifacts inside", found.join(", ")));
    }

    Ok(ExtractedArtifacts {
        evtx_dir: evtx_output_dir,
        linux_logs_dir: if total_linux_logs > 0 { Some(linux_logs_dir) } else { None },
        tasks_dir: if total_tasks > 0 { Some(tasks_dir) } else { None },
    })
}

/// GPT partition type GUID for Microsoft Basic Data (includes NTFS)
const GPT_BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Find NTFS partition offsets by scanning MBR, GPT, and common offsets.
fn find_ntfs_partitions<R: Read + Seek>(
    reader: &mut R,
    image_size: u64,
) -> Result<Vec<u64>, String> {
    let mut partitions = Vec::new();

    reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut mbr_buf = [0u8; 512];
    if reader.read_exact(&mut mbr_buf).is_ok() && mbr_buf[510] == 0x55 && mbr_buf[511] == 0xAA {
        // Check if this is a protective MBR (GPT disk)
        let part0_type = mbr_buf[446 + 4];

        if part0_type == 0xEE {
            // GPT disk — parse GPT header and partition entries
            if is_debug_mode() {
                eprintln!("[DEBUG] GPT protective MBR detected");
            }

            // GPT header at LBA 1 (offset 512)
            reader.seek(SeekFrom::Start(512)).map_err(|e| e.to_string())?;
            let mut gpt_header = [0u8; 92];
            if reader.read_exact(&mut gpt_header).is_ok() {
                // Verify "EFI PART" signature
                if &gpt_header[0..8] == b"EFI PART" {
                    let entry_start_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
                    let entry_count = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap());
                    let entry_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap());

                    if is_debug_mode() {
                        eprintln!("[DEBUG] GPT: {} entries, {} bytes each, starting at LBA {}",
                            entry_count, entry_size, entry_start_lba);
                    }

                    let entries_offset = entry_start_lba * 512;
                    for i in 0..entry_count.min(128) {
                        let entry_offset = entries_offset + (i as u64 * entry_size as u64);
                        reader.seek(SeekFrom::Start(entry_offset)).map_err(|e| e.to_string())?;
                        let mut entry = vec![0u8; entry_size as usize];
                        if reader.read_exact(&mut entry).is_err() {
                            continue;
                        }

                        // Check partition type GUID (first 16 bytes)
                        let type_guid: [u8; 16] = entry[0..16].try_into().unwrap();
                        if type_guid == [0u8; 16] {
                            continue; // empty entry
                        }

                        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
                        let partition_byte_offset = first_lba * 512;

                        // Check if it's a Basic Data partition (NTFS/FAT) or just verify NTFS signature
                        if type_guid == GPT_BASIC_DATA_GUID || verify_ntfs_signature(reader, partition_byte_offset) {
                            if verify_ntfs_signature(reader, partition_byte_offset) {
                                if is_debug_mode() {
                                    eprintln!("[DEBUG] GPT partition {} at LBA {} (offset {:#x}) — NTFS confirmed",
                                        i, first_lba, partition_byte_offset);
                                }
                                partitions.push(partition_byte_offset);
                            }
                        }
                    }
                }
            }
        } else {
            // Standard MBR — parse 4 primary partition entries
            for i in 0..4 {
                let entry_offset = 446 + i * 16;
                let part_type = mbr_buf[entry_offset + 4];
                let lba_start = u32::from_le_bytes([
                    mbr_buf[entry_offset + 8],
                    mbr_buf[entry_offset + 9],
                    mbr_buf[entry_offset + 10],
                    mbr_buf[entry_offset + 11],
                ]);

                if part_type == 0x07 && lba_start > 0 {
                    let offset = lba_start as u64 * 512;
                    if verify_ntfs_signature(reader, offset) {
                        partitions.push(offset);
                    }
                }
            }
        }
    }

    // Fallback: check if the image starts with NTFS directly (partition image)
    if partitions.is_empty() {
        if verify_ntfs_signature(reader, 0) {
            partitions.push(0);
        }
    }

    Ok(partitions)
}

/// Check if an NTFS boot sector signature exists at the given offset
fn verify_ntfs_signature<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 3)).is_err() {
        return false;
    }
    let mut sig = [0u8; 8];
    if reader.read_exact(&mut sig).is_err() {
        return false;
    }
    &sig == NTFS_SIGNATURE
}

/// Extract EVTX files from an NTFS partition at the given offset
fn extract_evtx_from_ntfs_partition<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    output_dir: &Path,
    partition_index: usize,
) -> Result<usize, String> {
    // Create a partition-offset reader wrapper
    let mut partition_reader = OffsetReader::new(reader, partition_offset);

    // Open NTFS
    let mut ntfs = ntfs::Ntfs::new(&mut partition_reader)
        .map_err(|e| format!("Cannot parse NTFS: {}", e))?;
    ntfs.read_upcase_table(&mut partition_reader)
        .map_err(|e| format!("Cannot read upcase table: {}", e))?;

    // Navigate to Windows\System32\winevt\Logs
    let root_dir = ntfs.root_directory(&mut partition_reader)
        .map_err(|e| format!("Cannot read root directory: {}", e))?;

    let mut current_dir = root_dir;
    for component in EVTX_LOGS_PATH {
        let index = current_dir.directory_index(&mut partition_reader)
            .map_err(|e| format!("Cannot read directory index: {}", e))?;

        let mut found = false;
        let mut entries = index.entries();
        while let Some(entry) = entries.next(&mut partition_reader) {
            let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
            if let Some(key) = entry.key() {
                let file_name = key.map_err(|e| format!("Filename error: {}", e))?;
                let name = file_name.name().to_string_lossy();
                if name.eq_ignore_ascii_case(component) {
                    let file_ref = entry.file_reference();
                    current_dir = file_ref.to_file(&ntfs, &mut partition_reader)
                        .map_err(|e| format!("Cannot open directory {}: {}", component, e))?;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(format!("Directory not found: {}", component));
        }
    }

    // We're now in the Logs directory — extract all .evtx files
    let logs_index = current_dir.directory_index(&mut partition_reader)
        .map_err(|e| format!("Cannot read Logs directory: {}", e))?;

    let mut count = 0;
    let partition_dir = output_dir.join(format!("partition_{}", partition_index));
    let _ = fs::create_dir_all(&partition_dir);

    let mut entries = logs_index.entries();
    while let Some(entry) = entries.next(&mut partition_reader) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(key) = entry.key() {
            let file_name = match key {
                Ok(f) => f,
                Err(_) => continue,
            };

            let name = file_name.name().to_string_lossy().to_string();
            if !name.to_lowercase().ends_with(".evtx") {
                continue;
            }

            // Read this EVTX file
            let file_ref = entry.file_reference();
            let ntfs_file = match file_ref.to_file(&ntfs, &mut partition_reader) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let data_item = match ntfs_file.data(&mut partition_reader, "") {
                Some(Ok(d)) => d,
                _ => continue,
            };

            let data_attr = match data_item.to_attribute() {
                Ok(a) => a,
                Err(_) => continue,
            };

            let data_value = match data_attr.value(&mut partition_reader) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Attach the reader to get a std::io::Read implementation
            let mut attached = data_value.attach(&mut partition_reader);

            // Write to output directory
            let output_path = partition_dir.join(&name);
            let mut output_file = match File::create(&output_path) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let mut buf = [0u8; 65536];
            loop {
                let bytes_read = match attached.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if output_file.write_all(&buf[..bytes_read]).is_err() {
                    break;
                }
            }

            count += 1;
            if is_debug_mode() {
                eprintln!("[DEBUG] Extracted: {} ({} bytes)", name, output_path.metadata().map(|m| m.len()).unwrap_or(0));
            }
        }
    }

    Ok(count)
}

/// Extract EVTX files from a VSS store reader (which implements Read+Seek).
fn extract_evtx_from_vss_store<R: Read + Seek>(
    store_reader: &mut R,
    output_dir: &Path,
    partition_index: usize,
    store_index: usize,
) -> Result<usize, String> {
    let mut ntfs = ntfs::Ntfs::new(store_reader)
        .map_err(|e| format!("Cannot parse NTFS from VSS store: {}", e))?;
    ntfs.read_upcase_table(store_reader)
        .map_err(|e| format!("Cannot read upcase table from VSS: {}", e))?;

    let root_dir = ntfs.root_directory(store_reader)
        .map_err(|e| format!("Cannot read root directory from VSS: {}", e))?;

    // Navigate to Windows\System32\winevt\Logs
    let mut current_dir = root_dir;
    for component in EVTX_LOGS_PATH {
        let index = current_dir.directory_index(store_reader)
            .map_err(|e| format!("Cannot read directory index: {}", e))?;

        let mut found = false;
        let mut entries = index.entries();
        while let Some(entry) = entries.next(store_reader) {
            let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
            if let Some(key) = entry.key() {
                let file_name = key.map_err(|e| format!("Filename error: {}", e))?;
                let name = file_name.name().to_string_lossy();
                if name.eq_ignore_ascii_case(component) {
                    let file_ref = entry.file_reference();
                    current_dir = file_ref.to_file(&ntfs, store_reader)
                        .map_err(|e| format!("Cannot open directory {}: {}", component, e))?;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(format!("Directory not found in VSS: {}", component));
        }
    }

    let logs_index = current_dir.directory_index(store_reader)
        .map_err(|e| format!("Cannot read Logs directory from VSS: {}", e))?;

    let mut count = 0;
    let vss_dir = output_dir.join(format!("partition_{}_vss_{}", partition_index, store_index));
    let _ = fs::create_dir_all(&vss_dir);

    let mut entries = logs_index.entries();
    while let Some(entry) = entries.next(store_reader) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if let Some(key) = entry.key() {
            let file_name = match key { Ok(f) => f, Err(_) => continue };
            let name = file_name.name().to_string_lossy().to_string();
            if !name.to_lowercase().ends_with(".evtx") { continue; }

            let file_ref = entry.file_reference();
            let ntfs_file = match file_ref.to_file(&ntfs, store_reader) { Ok(f) => f, Err(_) => continue };
            let data_item = match ntfs_file.data(store_reader, "") { Some(Ok(d)) => d, _ => continue };
            let data_attr = match data_item.to_attribute() { Ok(a) => a, Err(_) => continue };
            let data_value = match data_attr.value(store_reader) { Ok(v) => v, Err(_) => continue };
            let mut attached = data_value.attach(store_reader);

            let output_path = vss_dir.join(&name);
            let mut output_file = match File::create(&output_path) { Ok(f) => f, Err(_) => continue };

            let mut buf = [0u8; 65536];
            loop {
                match attached.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => { let _ = output_file.write_all(&buf[..n]); }
                    Err(_) => break,
                }
            }
            count += 1;
        }
    }

    Ok(count)
}

/// Extract files with a given extension from an NTFS path.
/// Used to extract UAL .mdb files from Windows/System32/LogFiles/Sum.
fn extract_files_from_ntfs_path<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    path_components: &[&str],
    extension: &str,
    output_dir: &Path,
) -> Result<usize, String> {
    let mut partition_reader = OffsetReader::new(reader, partition_offset);

    let mut ntfs = ntfs::Ntfs::new(&mut partition_reader)
        .map_err(|e| format!("Cannot parse NTFS: {}", e))?;
    ntfs.read_upcase_table(&mut partition_reader)
        .map_err(|e| format!("Cannot read upcase table: {}", e))?;

    let root_dir = ntfs.root_directory(&mut partition_reader)
        .map_err(|e| format!("Cannot read root directory: {}", e))?;

    let mut current_dir = root_dir;
    for component in path_components {
        let index = current_dir.directory_index(&mut partition_reader)
            .map_err(|e| format!("Cannot read directory index: {}", e))?;
        let mut found = false;
        let mut entries = index.entries();
        while let Some(entry) = entries.next(&mut partition_reader) {
            let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
            if let Some(key) = entry.key() {
                let file_name = key.map_err(|e| format!("Filename error: {}", e))?;
                let name = file_name.name().to_string_lossy();
                if name.eq_ignore_ascii_case(component) {
                    current_dir = entry.file_reference().to_file(&ntfs, &mut partition_reader)
                        .map_err(|e| format!("Cannot open directory {}: {}", component, e))?;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(format!("Path not found: {}", component));
        }
    }

    let _ = fs::create_dir_all(output_dir);
    let dir_index = current_dir.directory_index(&mut partition_reader)
        .map_err(|e| format!("Cannot read directory: {}", e))?;

    let mut count = 0;
    let mut entries = dir_index.entries();
    while let Some(entry) = entries.next(&mut partition_reader) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if let Some(key) = entry.key() {
            let file_name = match key { Ok(f) => f, Err(_) => continue };
            let name = file_name.name().to_string_lossy().to_string();
            if !name.to_lowercase().ends_with(&format!(".{}", extension)) { continue; }

            let ntfs_file = match entry.file_reference().to_file(&ntfs, &mut partition_reader) {
                Ok(f) => f, Err(_) => continue
            };
            let data_item = match ntfs_file.data(&mut partition_reader, "") {
                Some(Ok(d)) => d, _ => continue
            };
            let data_attr = match data_item.to_attribute() { Ok(a) => a, Err(_) => continue };
            let data_value = match data_attr.value(&mut partition_reader) { Ok(v) => v, Err(_) => continue };
            let mut attached = data_value.attach(&mut partition_reader);

            let output_path = output_dir.join(&name);
            let mut output_file = match File::create(&output_path) { Ok(f) => f, Err(_) => continue };

            let mut buf = [0u8; 65536];
            loop {
                match attached.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => { let _ = output_file.write_all(&buf[..n]); }
                    Err(_) => break,
                }
            }
            count += 1;
        }
    }

    Ok(count)
}

/// Extract ALL files (no extension filter) from an NTFS path, recursively.
/// Used to extract Scheduled Task XML files from Windows/System32/Tasks.
fn extract_all_files_from_ntfs_path<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    path_components: &[&str],
    output_dir: &Path,
) -> Result<usize, String> {
    let mut partition_reader = OffsetReader::new(reader, partition_offset);

    let mut ntfs = ntfs::Ntfs::new(&mut partition_reader)
        .map_err(|e| format!("Cannot parse NTFS: {}", e))?;
    ntfs.read_upcase_table(&mut partition_reader)
        .map_err(|e| format!("Cannot read upcase table: {}", e))?;

    let root_dir = ntfs.root_directory(&mut partition_reader)
        .map_err(|e| format!("Cannot read root directory: {}", e))?;

    // Navigate to the target directory
    let mut current_dir = root_dir;
    for component in path_components {
        let index = current_dir.directory_index(&mut partition_reader)
            .map_err(|e| format!("Cannot read directory index: {}", e))?;
        let mut found = false;
        let mut entries = index.entries();
        while let Some(entry) = entries.next(&mut partition_reader) {
            let entry = entry.map_err(|e| format!("Directory entry error: {}", e))?;
            if let Some(key) = entry.key() {
                let file_name = key.map_err(|e| format!("Filename error: {}", e))?;
                let name = file_name.name().to_string_lossy();
                if name.eq_ignore_ascii_case(component) {
                    current_dir = entry.file_reference().to_file(&ntfs, &mut partition_reader)
                        .map_err(|e| format!("Cannot open directory {}: {}", component, e))?;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(format!("Path not found: {}", component));
        }
    }

    let _ = fs::create_dir_all(output_dir);
    extract_files_recursive(&ntfs, &current_dir, &mut partition_reader, output_dir)
}

/// Recursively extract all files from an NTFS directory.
fn extract_files_recursive<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    output_dir: &Path,
) -> Result<usize, String> {
    let dir_index = dir.directory_index(reader)
        .map_err(|e| format!("Cannot read directory: {}", e))?;

    let mut count = 0;
    let mut subdirs: Vec<(String, ntfs::NtfsFileReference)> = Vec::new();

    let mut entries = dir_index.entries();
    while let Some(entry) = entries.next(reader) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if let Some(key) = entry.key() {
            let file_name = match key { Ok(f) => f, Err(_) => continue };
            let name = file_name.name().to_string_lossy().to_string();

            // Skip . and .. and system files
            if name == "." || name == ".." || name.starts_with('$') { continue; }

            let is_directory = file_name.is_directory();
            if is_directory {
                subdirs.push((name, entry.file_reference()));
            } else {
                // Extract file
                let ntfs_file = match entry.file_reference().to_file(ntfs, reader) {
                    Ok(f) => f, Err(_) => continue
                };
                let data_item = match ntfs_file.data(reader, "") {
                    Some(Ok(d)) => d, _ => continue
                };
                let data_attr = match data_item.to_attribute() { Ok(a) => a, Err(_) => continue };
                let data_value = match data_attr.value(reader) { Ok(v) => v, Err(_) => continue };
                let mut attached = data_value.attach(reader);

                let output_path = output_dir.join(&name);
                let mut output_file = match File::create(&output_path) { Ok(f) => f, Err(_) => continue };

                let mut buf = [0u8; 65536];
                loop {
                    match attached.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => { let _ = output_file.write_all(&buf[..n]); }
                        Err(_) => break,
                    }
                }
                count += 1;
            }
        }
    }

    // Recurse into subdirectories
    for (name, file_ref) in subdirs {
        let subdir = match file_ref.to_file(ntfs, reader) {
            Ok(f) => f, Err(_) => continue
        };
        let subdir_path = output_dir.join(&name);
        match extract_files_recursive(ntfs, &subdir, reader, &subdir_path) {
            Ok(c) => count += c,
            Err(_) => {}
        }
    }

    Ok(count)
}

/// Rewrite the log_filename column in the output CSV.
/// Replaces temp paths like ".../partition_0/Security.evtx" with "ImageName.e01:live:Security.evtx"
/// and ".../partition_0_vss_0/Security.evtx" with "ImageName.e01:vss_0:Security.evtx"
/// Rewrite log_filename column: clean temp paths to descriptive format.
/// "...masstin_image_extract/HRServer.e01/evtx_extracted/partition_0_vss_0/Security.evtx"
///   → "HRServer.e01:vss_0:Security.evtx"
/// "...masstin_image_extract/HRServer.e01/evtx_extracted:UAL:Current.mdb"
///   → "HRServer.e01:UAL:Current.mdb"
fn rewrite_log_filenames(csv_path: &str) {
    let content = match fs::read_to_string(csv_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut output = String::with_capacity(content.len());
    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            output.push_str(line);
            output.push('\n');
            continue;
        }

        if let Some(last_comma) = line.rfind(',') {
            let prefix = &line[..last_comma + 1];
            let filename_field = &line[last_comma + 1..];

            if !filename_field.contains("masstin_image_extract") {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Extract image name: segment after "masstin_image_extract/" or "masstin_image_extract\"
            let rewritten = rewrite_single_filename(filename_field);
            output.push_str(prefix);
            output.push_str(&rewritten);
            output.push('\n');
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }

    let _ = fs::write(csv_path, output);
}

fn rewrite_single_filename(path: &str) -> String {
    // Split by path separators and "masstin_image_extract"
    let normalized = path.replace('\\', "/");

    // Find the image name (segment after masstin_image_extract/)
    let marker = "masstin_image_extract/";
    let after_marker = match normalized.find(marker) {
        Some(pos) => &normalized[pos + marker.len()..],
        None => return path.to_string(),
    };

    // after_marker = "HRServer_Disk0.e01/evtx_extracted/partition_0_vss_0/Security.evtx"
    // or "HRServer_Disk0.e01/evtx_extracted:UAL:Current.mdb"
    let parts: Vec<&str> = after_marker.splitn(2, '/').collect();
    let image_name = parts[0];
    let rest = if parts.len() > 1 { parts[1] } else { "" };

    // Handle UAL paths (contain ":UAL:")
    if rest.contains(":UAL:") {
        let ual_part = rest.rsplit(":UAL:").next().unwrap_or(rest);
        return format!("{}:UAL:{}", image_name, ual_part);
    }

    // Get the EVTX filename
    let evtx_name = rest.rsplit('/').next().unwrap_or(rest);

    // Determine source: live or vss_N
    let source = if rest.contains("_vss_") {
        if let Some(vss_pos) = rest.find("_vss_") {
            let after_vss = &rest[vss_pos + 1..];
            let end = after_vss.find('/').unwrap_or(after_vss.len());
            &after_vss[..end]
        } else {
            "vss"
        }
    } else {
        "live"
    };

    format!("{}:{}:{}", image_name, source, evtx_name)
}

/// Wrapper that adds a byte offset to all Read/Seek operations.
/// This allows treating a partition within an image as if it were a standalone volume.
struct OffsetReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> OffsetReader<'a, R> {
    fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<'a, R: Read + Seek> Read for OffsetReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, R: Read + Seek> Seek for OffsetReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => {
                let actual = self.inner.seek(SeekFrom::Start(self.offset + p))?;
                Ok(actual - self.offset)
            }
            SeekFrom::Current(p) => {
                let actual = self.inner.seek(SeekFrom::Current(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::End(p) => {
                // For partition reader, End is relative to the inner stream's end
                let actual = self.inner.seek(SeekFrom::End(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}
