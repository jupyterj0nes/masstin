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

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const EVTX_LOGS_PATH: &[&str] = &["Windows", "System32", "winevt", "Logs"];
const UAL_SUM_PATH: &[&str] = &["Windows", "System32", "LogFiles", "Sum"];

/// Main entry point: parse EVTX files from forensic disk images, mounted volumes, or all volumes.
/// All sources are extracted to temp directories first, then parsed together into a single CSV.
pub fn parse_image_windows(files: &[String], directories: &[String], all_volumes: bool, output: Option<&String>) {
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

        for dir in &real_dirs {
            crate::banner::print_info(&format!("Scanning {} for forensic images...", dir));
            scan_for_images(Path::new(dir), &image_extensions, &mut discovered, 0);
        }

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
            for img in &filtered {
                crate::banner::print_info(&format!("  {}", img));
            }

            // Add discovered images to the processing list
            all_image_files.extend(filtered);
        }
    }

    // Extract from image files — use image name as temp subdirectory
    for image_path in &all_image_files {
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

        crate::banner::print_info(&format!("Opening forensic image: {}...", image_name));

        let temp_dir = base_temp.join(&image_name);
        let _ = fs::create_dir_all(&temp_dir);

        let evtx_dir = match ext.as_str() {
            "e01" | "ex01" => {
                crate::banner::print_info(&format!("Image format: E01 ({})", image_path));
                extract_evtx_from_image_ewf(image_path, &temp_dir)
            }
            "vmdk" => {
                crate::banner::print_info(&format!("Image format: VMDK ({})", image_path));
                extract_evtx_from_image_vmdk(image_path, &temp_dir)
            }
            "dd" | "raw" | "img" | "001" => {
                crate::banner::print_info(&format!("Image format: raw/dd ({})", image_path));
                extract_evtx_from_image_raw(image_path, &temp_dir)
            }
            _ => {
                crate::banner::print_info(&format!("Unknown extension, trying raw then E01 ({})", image_path));
                extract_evtx_from_image_raw(image_path, &temp_dir)
                    .or_else(|_| extract_evtx_from_image_ewf(image_path, &temp_dir))
            }
        };

        match evtx_dir {
            Ok(dir) => {
                crate::banner::print_phase_result(&format!("EVTX files extracted from {}", image_name));
                extracted_dirs.push(dir.to_string_lossy().to_string());
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to process image {}: {}", image_path, e);
            }
        }
    }

    // Add real directories (loose EVTX files)
    for d in &real_dirs {
        extracted_dirs.push(d.clone());
    }

    if extracted_dirs.is_empty() {
        eprintln!("[ERROR] No artifacts extracted from any source.");
        return;
    }

    // Phase 2+3: Parse ALL extracted directories together into a single CSV
    let empty_files: Vec<String> = vec![];
    parse_events(&empty_files, &extracted_dirs, output);

    // Rewrite log_filename: clean up temp paths to descriptive format
    // e.g. "...masstin_image_extract/HRServer.e01/evtx_extracted/partition_0_vss_0/Security.evtx"
    //   → "HRServer.e01:vss_0:Security.evtx"
    if let Some(out_path) = output {
        rewrite_log_filenames(out_path);
    }

    // Cleanup temp directories
    let _ = fs::remove_dir_all(&base_temp);
}

// -----------------------------------------------------------------------------
//  Drive letter detection and volume enumeration
// -----------------------------------------------------------------------------

/// Recursively scan a directory for forensic image files.
fn scan_for_images(dir: &Path, extensions: &[&str], results: &mut Vec<String>, depth: usize) {
    if depth > 10 { return; } // Avoid infinite recursion
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip $RECYCLE.BIN and other system dirs
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('$') || name.starts_with('.') || name == "System Volume Information" {
                continue;
            }
            scan_for_images(&path, extensions, results, depth + 1);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.iter().any(|x| x.eq_ignore_ascii_case(ext)) {
                    results.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
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
fn extract_evtx_from_image_ewf(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let reader = ewf::EwfReader::open(image_path)
        .map_err(|e| format!("Cannot open E01: {}", e))?;

    let image_size = reader.total_size();
    crate::banner::print_info(&format!("Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0));

    let mut buf_reader = BufReader::new(reader);
    extract_evtx_from_seekable(&mut buf_reader, image_size, temp_dir)
}

/// Extract EVTX from a VMDK image
fn extract_evtx_from_image_vmdk(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let reader = crate::vmdk::VmdkReader::open(image_path)
        .map_err(|e| format!("Cannot open VMDK: {}", e))?;

    let image_size = reader.total_size();
    crate::banner::print_info(&format!("Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0));

    let mut buf_reader = BufReader::new(reader);
    extract_evtx_from_seekable(&mut buf_reader, image_size, temp_dir)
}

/// Extract EVTX from a raw/dd image
fn extract_evtx_from_image_raw(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let file = File::open(image_path)
        .map_err(|e| format!("Cannot open raw image: {}", e))?;

    let image_size = file.metadata()
        .map_err(|e| format!("Cannot read file size: {}", e))?
        .len();

    crate::banner::print_info(&format!("Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0));

    let mut buf_reader = BufReader::new(file);
    extract_evtx_from_seekable(&mut buf_reader, image_size, temp_dir)
}

/// Core logic: find NTFS partitions and extract EVTX files
fn extract_evtx_from_seekable<R: Read + Seek>(
    reader: &mut R,
    image_size: u64,
    temp_dir: &Path,
) -> Result<PathBuf, String> {
    crate::banner::print_info("Searching for NTFS partitions...");

    // Find NTFS partition offsets
    let partitions = find_ntfs_partitions(reader, image_size)?;

    if partitions.is_empty() {
        return Err("No NTFS partitions found in image".to_string());
    }

    crate::banner::print_phase_result(&format!("{} NTFS partition(s) found", partitions.len()));

    let evtx_output_dir = temp_dir.join("evtx_extracted");
    let _ = fs::create_dir_all(&evtx_output_dir);
    let mut total_evtx = 0;

    for (i, partition_offset) in partitions.iter().enumerate() {
        crate::banner::print_info(&format!(
            "Partition {} at offset {:#x} ({:.2} GB)",
            i + 1,
            partition_offset,
            *partition_offset as f64 / 1_073_741_824.0
        ));

        // Extract EVTX from the live (current) volume
        match extract_evtx_from_ntfs_partition(reader, *partition_offset, &evtx_output_dir, i) {
            Ok(count) => {
                total_evtx += count;
                crate::banner::print_info(&format!("  {} EVTX files extracted from live volume", count));
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Partition {} error: {}", i + 1, e);
                }
            }
        }

        // Extract UAL databases from live volume
        let ual_dir = evtx_output_dir.join(format!("partition_{}", i)).join("Sum");
        match extract_files_from_ntfs_path(reader, *partition_offset, UAL_SUM_PATH, "mdb", &ual_dir) {
            Ok(count) if count > 0 => {
                crate::banner::print_info(&format!("  {} UAL database files extracted from live volume", count));
            }
            _ => {}
        }

        // Check for Volume Shadow Copies (VSS) and extract EVTX from each
        let mut offset_reader = OffsetReader::new(reader, *partition_offset);
        match VssVolume::new(&mut offset_reader) {
            Ok(vss) if vss.store_count() > 0 => {
                crate::banner::print_phase_result(&format!(
                    "{} Volume Shadow Copy snapshot(s) detected", vss.store_count()
                ));

                for s in 0..vss.store_count() {
                    let store_label = format!("vss_{}", s);
                    crate::banner::print_info(&format!("  Processing VSS store {}...", s));

                    // Show delta info
                    if let Ok((blocks, bytes)) = vss.store_delta_size(&mut offset_reader, s) {
                        crate::banner::print_info(&format!("    {} changed blocks ({:.1} MB delta)",
                            blocks, bytes as f64 / 1_048_576.0));
                    }

                    match vss.store_reader(&mut offset_reader, s) {
                        Ok(mut store_reader) => {
                            crate::banner::print_info("    Opening NTFS from VSS snapshot...");
                            // Try to parse NTFS from this VSS store
                            match extract_evtx_from_vss_store(&mut store_reader, &evtx_output_dir, i, s) {
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
                crate::banner::print_info("No Volume Shadow Copies detected");
            }
            Err(_) => {
                crate::banner::print_info("No Volume Shadow Copies detected");
            }
        }
    }

    if total_evtx == 0 {
        return Err("No EVTX files found in any NTFS partition".to_string());
    }

    crate::banner::print_phase_result(&format!("{} EVTX files extracted total", total_evtx));
    Ok(evtx_output_dir)
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
