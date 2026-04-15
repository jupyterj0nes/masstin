// -----------------------------------------------------------------------------
//  Forensic image parser for Linux logs
//  Opens E01/dd/VMDK images, finds ext4/ext3/ext2 partitions, extracts log
//  files (auth.log, secure, messages, audit.log, utmp, wtmp, btmp, lastlog,
//  hostname, dpkg.log) to a temp directory, then delegates to parse_linux().
// -----------------------------------------------------------------------------

use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use ext4_view::{Ext4, Ext4Read};
use crate::parse::is_debug_mode;
use crate::parse_linux::parse_linux;

/// GPT partition type GUID for Linux LVM
/// E6D6D379-F507-44C2-A23C-238F2A3DF928 in mixed-endian encoding
const GPT_LINUX_LVM_GUID: [u8; 16] = [
    0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44,
    0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28,
];

/// GPT partition type GUID for Linux filesystem
/// 0FC63DAF-8483-4772-8E79-3D69D8477DE4 in mixed-endian encoding
const GPT_LINUX_FS_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// ext4 superblock magic number at offset 0x438 from partition start (1024 + 56)
const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Directories and files to extract from ext4 partitions
const LOG_DIRS: &[&str] = &[
    "/var/log",
    "/var/log/audit",
];

/// Well-known file prefixes to look for inside /var/log/
const LOG_PREFIXES: &[&str] = &[
    "auth.log",
    "secure",
    "messages",
    "audit.log",
    "dpkg.log",
];

/// Individual files to extract (exact paths)
const EXACT_FILES: &[&str] = &[
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/etc/hostname",
];

// -----------------------------------------------------------------------------
//  Public entry point
// -----------------------------------------------------------------------------

/// Parse Linux forensic logs from disk images (E01, dd, VMDK).
/// Extracts auth.log, secure, messages, audit.log, utmp, wtmp, btmp, lastlog
/// from ext4/ext3/ext2 partitions, then passes them to parse_linux().
pub fn parse_image_linux(files: &[String], directories: &[String], output: Option<&String>) {
    let _start_time = std::time::Instant::now();

    // Phase 1: Collect image files
    let mut all_image_files: Vec<String> = files.to_vec();

    // Scan directories for forensic images
    let image_extensions = ["e01", "ex01", "vmdk", "dd", "raw", "img", "001"];
    for dir in directories {
        crate::banner::print_info(&format!("Scanning {} for forensic images...", dir));
        scan_for_images(Path::new(dir), &image_extensions, &mut all_image_files, 0);
    }

    // Deduplicate: for E01 split files, only keep .E01; for VMDK, only keep descriptors
    let all_image_files: Vec<String> = all_image_files.into_iter().filter(|p| {
        let name = Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or("");
        let lower = name.to_lowercase();
        if lower.ends_with(".e01") || lower.ends_with(".ex01") { return true; }
        if lower.ends_with(".vmdk") {
            let stem = Path::new(p).file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let stem_lower = stem.to_lowercase();
            if stem_lower.ends_with("-flat") { return false; }
            if let Some(pos) = stem.rfind("-s") {
                let after = &stem[pos + 2..];
                if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
                    return false;
                }
            }
            if let Some(pos) = stem.rfind("-0") {
                let after = &stem[pos + 1..];
                if after.len() >= 6 && after[..6].chars().all(|c| c.is_ascii_digit()) {
                    return false;
                }
            }
            return true;
        }
        true
    }).collect();

    if all_image_files.is_empty() {
        eprintln!("[ERROR] No forensic images found.");
        return;
    }

    crate::banner::print_phase_result(&format!(
        "{} forensic image(s) to process", all_image_files.len()
    ));
    for img in &all_image_files {
        crate::banner::print_info(&format!("  {}", img));
    }

    // Phase 2: Extract logs from each image
    let base_temp = std::env::temp_dir().join("masstin_linux_image_extract");
    let _ = fs::remove_dir_all(&base_temp);
    let _ = fs::create_dir_all(&base_temp);

    let mut extracted_dirs: Vec<String> = Vec::new();

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

        crate::banner::print_phase("1", "3", &format!("Opening forensic image: {}...", image_name));

        let temp_dir = base_temp.join(&image_name);
        let _ = fs::create_dir_all(&temp_dir);

        let result = match ext.as_str() {
            "e01" | "ex01" => {
                crate::banner::print_info(&format!("Image format: E01 ({})", image_path));
                extract_logs_from_image_ewf(image_path, &temp_dir)
            }
            "vmdk" => {
                crate::banner::print_info(&format!("Image format: VMDK ({})", image_path));
                extract_logs_from_image_vmdk(image_path, &temp_dir)
            }
            "dd" | "raw" | "img" | "001" => {
                crate::banner::print_info(&format!("Image format: raw/dd ({})", image_path));
                extract_logs_from_image_raw(image_path, &temp_dir)
            }
            _ => {
                crate::banner::print_info(&format!("Unknown extension, trying raw then E01 ({})", image_path));
                extract_logs_from_image_raw(image_path, &temp_dir)
                    .or_else(|_| extract_logs_from_image_ewf(image_path, &temp_dir))
            }
        };

        match result {
            Ok(dir) => {
                crate::banner::print_phase_result(&format!("Linux logs extracted from {}", image_name));
                extracted_dirs.push(dir.to_string_lossy().to_string());
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to process image {}: {}", image_path, e);
            }
        }
    }

    if extracted_dirs.is_empty() {
        eprintln!("[ERROR] No Linux log artifacts extracted from any image.");
        return;
    }

    // Phase 3: Pass extracted directories to parse_linux
    let empty_files: Vec<String> = vec![];
    parse_linux(&empty_files, &extracted_dirs, output);

    // Rewrite log_filename: replace temp paths with ImageName.e01:partition_0:/var/log/auth.log
    if let Some(out_path) = output {
        rewrite_log_filenames_linux(out_path);
    }

    // Cleanup
    let _ = fs::remove_dir_all(&base_temp);
}

// -----------------------------------------------------------------------------
//  Image format openers
// -----------------------------------------------------------------------------

fn extract_logs_from_image_ewf(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let reader = ewf::EwfReader::open(image_path)
        .map_err(|e| format!("Cannot open E01: {}", e))?;

    let image_size = reader.total_size();
    crate::banner::print_info(&format!("Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0));

    let mut buf_reader = BufReader::new(reader);
    extract_logs_from_seekable(&mut buf_reader, image_size, image_path, temp_dir)
}

fn extract_logs_from_image_vmdk(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let reader = crate::vmdk::VmdkReader::open(image_path)
        .map_err(|e| format!("Cannot open VMDK: {}", e))?;

    let image_size = reader.total_size();
    crate::banner::print_info(&format!("Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0));

    let mut buf_reader = BufReader::new(reader);
    extract_logs_from_seekable(&mut buf_reader, image_size, image_path, temp_dir)
}

fn extract_logs_from_image_raw(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let file = File::open(image_path)
        .map_err(|e| format!("Cannot open raw image: {}", e))?;

    let image_size = file.metadata()
        .map_err(|e| format!("Cannot read file size: {}", e))?
        .len();

    crate::banner::print_info(&format!("Image size: {:.2} GB", image_size as f64 / 1_073_741_824.0));

    let mut buf_reader = BufReader::new(file);
    extract_logs_from_seekable(&mut buf_reader, image_size, image_path, temp_dir)
}

// -----------------------------------------------------------------------------
//  Core extraction: find ext4 partitions & extract log files
// -----------------------------------------------------------------------------

fn extract_logs_from_seekable<R: Read + Seek + 'static>(
    reader: &mut R,
    image_size: u64,
    _image_path: &str,
    temp_dir: &Path,
) -> Result<PathBuf, String> {
    crate::banner::print_phase("1", "3", "Searching for ext4/ext3/ext2 partitions...");

    let partitions = find_linux_partitions(reader, image_size)?;

    if partitions.is_empty() {
        return Err("No ext4/ext3/ext2 partitions found in image".to_string());
    }

    crate::banner::print_phase_result(&format!("{} ext4 partition(s) found", partitions.len()));

    let logs_output_dir = temp_dir.join("logs_extracted");
    let _ = fs::create_dir_all(&logs_output_dir);
    let mut total_files = 0;

    for (i, partition_offset) in partitions.iter().enumerate() {
        crate::banner::print_info(&format!(
            "Partition {} at offset {:#x} ({:.2} GB)",
            i, partition_offset,
            *partition_offset as f64 / 1_073_741_824.0
        ));

        let partition_dir = logs_output_dir.join(format!("partition_{}", i));
        let _ = fs::create_dir_all(&partition_dir);

        match extract_logs_from_ext4_partition(reader, *partition_offset, &partition_dir) {
            Ok(count) => {
                total_files += count;
                crate::banner::print_info(&format!("  {} log files extracted from partition {}", count, i));
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] Partition {} error: {}", i, e);
                }
                crate::banner::print_info(&format!("  Could not read partition {}: {}", i, e));
            }
        }
    }

    // Try LVM partitions if we haven't found enough data
    let lvm_partitions = find_lvm_partitions(reader);
    if !lvm_partitions.is_empty() {
        crate::banner::print_info(&format!("{} LVM partition(s) found — scanning for logical volumes...", lvm_partitions.len()));

        for (li, lvm_offset) in lvm_partitions.iter().enumerate() {
            let count = extract_logs_from_lvm(reader, *lvm_offset, li, &logs_output_dir);
            total_files += count;
        }
    }

    if total_files == 0 {
        return Err("No Linux log files found in any partition (ext4 or LVM)".to_string());
    }

    crate::banner::print_phase_result(&format!("{} log files extracted total", total_files));
    Ok(logs_output_dir)
}

/// Extract logs from LVM logical volumes inside a partition.
/// Dumps each LV with ext4 to a temp file and then processes it.
fn extract_logs_from_lvm<R: Read + Seek + 'static>(
    reader: &mut R,
    lvm_offset: u64,
    lvm_index: usize,
    output_dir: &Path,
) -> usize {
    let mut total = 0;
    let mut lvm_reader = OffsetReaderLinux::new(reader, lvm_offset);

    let lvm = match lvm2::Lvm2::open(&mut lvm_reader) {
        Ok(l) => l,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[DEBUG] LVM at offset {:#x}: {:?}", lvm_offset, e);
            }
            return 0;
        }
    };

    // Collect LV names first to avoid borrow issues
    let lv_names: Vec<String> = lvm.lvs().map(|lv| lv.name().to_string()).collect();

    for lv_name in &lv_names {
        crate::banner::print_info(&format!("  LV '{}' found in LVM partition {}", lv_name, lvm_index));

        // Find this LV again and dump to temp file
        let lv = match lvm.lvs().find(|l| l.name() == lv_name.as_str()) {
            Some(l) => l,
            None => continue,
        };

        let mut olv = lvm.open_lv(lv, &mut lvm_reader);

        // Check ext4 superblock
        let mut sb_buf = [0u8; 2];
        if olv.seek(SeekFrom::Start(0x438)).is_err() || olv.read_exact(&mut sb_buf).is_err() {
            continue;
        }
        let magic = u16::from_le_bytes(sb_buf);
        if magic != EXT4_SUPER_MAGIC {
            crate::banner::print_info(&format!("    Not ext4 (magic: {:#06x}), skipping", magic));
            continue;
        }

        crate::banner::print_info("    ext4 confirmed — extracting logs...");

        // Dump LV to temp file so we can pass it to extract_logs_from_ext4_partition
        let tmp_path = std::env::temp_dir().join(format!("masstin_lvm_{}_{}.raw", lvm_index, lv_name));
        {
            if olv.seek(SeekFrom::Start(0)).is_err() { continue; }
            let mut tmp_file = match File::create(&tmp_path) { Ok(f) => f, Err(_) => continue };
            let mut buf = [0u8; 1048576]; // 1MB chunks
            loop {
                match olv.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => { if tmp_file.write_all(&buf[..n]).is_err() { break; } }
                    Err(_) => break,
                }
            }
        }

        // Now process the temp file as a regular ext4 partition
        let partition_dir = output_dir.join(format!("lvm_{}_lv_{}", lvm_index, lv_name));
        let _ = fs::create_dir_all(&partition_dir);

        let mut tmp_file = match File::open(&tmp_path) { Ok(f) => f, Err(_) => continue };
        match extract_logs_from_ext4_partition(&mut tmp_file, 0, &partition_dir) {
            Ok(count) if count > 0 => {
                total += count;
                crate::banner::print_info(&format!("    {} log files extracted from LV '{}'", count, lv_name));
            }
            Ok(_) => {
                crate::banner::print_info(&format!("    No log files found in LV '{}'", lv_name));
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] LV '{}' ext4 error: {}", lv_name, e);
                }
            }
        }

        // Cleanup temp file
        let _ = fs::remove_file(&tmp_path);
    }

    total
}

/// Simple offset reader for LVM partition access
struct OffsetReaderLinux<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> OffsetReaderLinux<'a, R> {
    fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<'a, R: Read + Seek> Read for OffsetReaderLinux<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, R: Read + Seek> Seek for OffsetReaderLinux<'a, R> {
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
                let actual = self.inner.seek(SeekFrom::End(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

// -----------------------------------------------------------------------------
//  Partition detection
// -----------------------------------------------------------------------------

/// Public wrapper for finding Linux partitions (used by parse_image unified)
pub fn find_linux_partitions_public<R: Read + Seek>(
    reader: &mut R,
    image_size: u64,
) -> Result<Vec<u64>, String> {
    find_linux_partitions(reader, image_size)
}

/// Public wrapper for extracting Linux logs from a single ext4 partition
pub fn extract_linux_logs_from_ext4<R: Read + Seek + 'static>(
    reader: &mut R,
    partition_offset: u64,
    output_dir: &Path,
    partition_index: usize,
) -> Result<usize, String> {
    let partition_dir = output_dir.join(format!("partition_{}", partition_index));
    let _ = std::fs::create_dir_all(&partition_dir);
    extract_logs_from_ext4_partition(reader, partition_offset, &partition_dir)
}

fn find_linux_partitions<R: Read + Seek>(
    reader: &mut R,
    _image_size: u64,
) -> Result<Vec<u64>, String> {
    let mut partitions = Vec::new();

    reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut mbr_buf = [0u8; 512];
    if reader.read_exact(&mut mbr_buf).is_ok() && mbr_buf[510] == 0x55 && mbr_buf[511] == 0xAA {
        let part0_type = mbr_buf[446 + 4];

        if part0_type == 0xEE {
            // GPT disk
            if is_debug_mode() {
                eprintln!("[DEBUG] GPT protective MBR detected");
            }

            reader.seek(SeekFrom::Start(512)).map_err(|e| e.to_string())?;
            let mut gpt_header = [0u8; 92];
            if reader.read_exact(&mut gpt_header).is_ok() && &gpt_header[0..8] == b"EFI PART" {
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

                    let type_guid: [u8; 16] = entry[0..16].try_into().unwrap();
                    if type_guid == [0u8; 16] {
                        continue;
                    }

                    let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
                    let partition_byte_offset = first_lba * 512;

                    // Check for Linux filesystem GUID or verify ext4 superblock
                    if type_guid == GPT_LINUX_FS_GUID || verify_ext4_superblock(reader, partition_byte_offset) {
                        if verify_ext4_superblock(reader, partition_byte_offset) {
                            if is_debug_mode() {
                                eprintln!("[DEBUG] GPT partition {} at LBA {} (offset {:#x}) -- ext4 confirmed",
                                    i, first_lba, partition_byte_offset);
                            }
                            partitions.push(partition_byte_offset);
                        }
                    }
                }
            }
        } else {
            // Standard MBR -- parse 4 primary partition entries
            for i in 0..4 {
                let entry_offset = 446 + i * 16;
                let part_type = mbr_buf[entry_offset + 4];
                let lba_start = u32::from_le_bytes([
                    mbr_buf[entry_offset + 8],
                    mbr_buf[entry_offset + 9],
                    mbr_buf[entry_offset + 10],
                    mbr_buf[entry_offset + 11],
                ]);

                // 0x83 = Linux native partition
                if part_type == 0x83 && lba_start > 0 {
                    let offset = lba_start as u64 * 512;
                    if verify_ext4_superblock(reader, offset) {
                        if is_debug_mode() {
                            eprintln!("[DEBUG] MBR partition {} at LBA {} (offset {:#x}) -- ext4 confirmed",
                                i, lba_start, offset);
                        }
                        partitions.push(offset);
                    }
                }
            }
        }
    }

    // Fallback: check if the image starts with ext4 directly (partition image)
    if partitions.is_empty() {
        if verify_ext4_superblock(reader, 0) {
            if is_debug_mode() {
                eprintln!("[DEBUG] ext4 superblock found at offset 0 (partition image)");
            }
            partitions.push(0);
        }
    }

    Ok(partitions)
}

/// Find LVM partitions (MBR type 0x8E or GPT LVM GUID)
fn find_lvm_partitions<R: Read + Seek>(
    reader: &mut R,
) -> Vec<u64> {
    let mut partitions = Vec::new();

    if reader.seek(SeekFrom::Start(0)).is_err() { return partitions; }
    let mut mbr_buf = [0u8; 512];
    if reader.read_exact(&mut mbr_buf).is_err() || mbr_buf[510] != 0x55 || mbr_buf[511] != 0xAA {
        return partitions;
    }

    let part0_type = mbr_buf[446 + 4];
    if part0_type == 0xEE {
        // GPT
        if reader.seek(SeekFrom::Start(512)).is_err() { return partitions; }
        let mut gpt_header = [0u8; 92];
        if reader.read_exact(&mut gpt_header).is_ok() && &gpt_header[0..8] == b"EFI PART" {
            let entry_start_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
            let entry_count = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap());
            let entry_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap());

            let entries_offset = entry_start_lba * 512;
            for i in 0..entry_count.min(128) {
                let entry_offset = entries_offset + (i as u64 * entry_size as u64);
                if reader.seek(SeekFrom::Start(entry_offset)).is_err() { continue; }
                let mut entry = vec![0u8; entry_size as usize];
                if reader.read_exact(&mut entry).is_err() { continue; }

                let type_guid: [u8; 16] = entry[0..16].try_into().unwrap();
                if type_guid == GPT_LINUX_LVM_GUID {
                    let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
                    let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
                    let offset = first_lba * 512;
                    let size = (last_lba - first_lba + 1) * 512;
                    if is_debug_mode() {
                        eprintln!("[DEBUG] GPT LVM partition {} at LBA {} (offset {:#x}, size {:.2} GB)",
                            i, first_lba, offset, size as f64 / 1_073_741_824.0);
                    }
                    partitions.push(offset);
                }
            }
        }
    } else {
        // MBR
        for i in 0..4 {
            let entry_offset = 446 + i * 16;
            let part_type = mbr_buf[entry_offset + 4];
            let lba_start = u32::from_le_bytes([
                mbr_buf[entry_offset + 8], mbr_buf[entry_offset + 9],
                mbr_buf[entry_offset + 10], mbr_buf[entry_offset + 11],
            ]);
            // 0x8E = Linux LVM
            if part_type == 0x8E && lba_start > 0 {
                let offset = lba_start as u64 * 512;
                if is_debug_mode() {
                    eprintln!("[DEBUG] MBR LVM partition {} at LBA {} (offset {:#x})", i, lba_start, offset);
                }
                partitions.push(offset);
            }
        }
    }
    partitions
}

/// Verify ext4 superblock magic (0xEF53) at partition_offset + 0x438
fn verify_ext4_superblock<R: Read + Seek>(reader: &mut R, partition_offset: u64) -> bool {
    // Superblock starts at offset 1024 from partition start; magic is at offset 56 within it
    let magic_offset = partition_offset + 1024 + 56; // 0x438
    if reader.seek(SeekFrom::Start(magic_offset)).is_err() {
        return false;
    }
    let mut magic_buf = [0u8; 2];
    if reader.read_exact(&mut magic_buf).is_err() {
        return false;
    }
    u16::from_le_bytes(magic_buf) == EXT4_SUPER_MAGIC
}

// -----------------------------------------------------------------------------
//  Extract log files from a single ext4 partition
// -----------------------------------------------------------------------------

fn extract_logs_from_ext4_partition<R: Read + Seek + 'static>(
    reader: &mut R,
    partition_offset: u64,
    output_dir: &Path,
) -> Result<usize, String> {
    // We need to give ext4-view ownership of a reader. Since we can't clone
    // our reader, we wrap it in an adapter. However, Ext4::load takes
    // Box<dyn Ext4Read> which means it owns the reader. We can't give away
    // our borrowed &mut R.
    //
    // Solution: read through the partition by re-creating the Ext4 with a
    // wrapper that borrows our reader via a raw pointer. This is safe because
    // we ensure the Ext4 is dropped before returning.
    let fs = {
        let wrapper = UnsafeReaderWrapper {
            reader: reader as *mut R,
            partition_offset,
        };
        Ext4::load(Box::new(wrapper))
            .map_err(|e| format!("Cannot load ext4 filesystem: {}", e))?
    };

    let mut count = 0;

    // 1. Extract exact-path files
    for path in EXACT_FILES {
        match fs.read(*path) {
            Ok(data) => {
                let dest = map_linux_path_to_local(path, output_dir);
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Ok(mut f) = File::create(&dest) {
                    let _ = f.write_all(&data);
                    count += 1;
                    if is_debug_mode() {
                        eprintln!("[DEBUG] Extracted: {} ({} bytes)", path, data.len());
                    }
                }
            }
            Err(_) => {
                // File doesn't exist in this partition, that's OK
            }
        }
    }

    // 2. Scan /var/log/ for log files matching our prefixes
    for log_dir in LOG_DIRS {
        let entries = match fs.read_dir(*log_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let file_name = match entry.file_name().as_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };

            // Check if this is a directory entry we care about
            let file_name_lower = file_name.to_lowercase();

            // Skip directories (. and ..)
            if file_name == "." || file_name == ".." {
                continue;
            }

            // Check if the filename matches any of our log prefixes
            let matches = LOG_PREFIXES.iter().any(|prefix| {
                file_name_lower.starts_with(&prefix.to_lowercase())
            });

            // Also match utmp/wtmp/btmp/lastlog directly in /var/log/
            let matches = matches
                || file_name_lower == "wtmp"
                || file_name_lower == "btmp"
                || file_name_lower == "lastlog";

            if !matches {
                continue;
            }

            let full_path = format!("{}/{}", log_dir, file_name);

            // Check if it's a regular file
            match entry.file_type() {
                Ok(ft) if ft.is_regular_file() => {}
                _ => continue,
            }

            match fs.read(full_path.as_str()) {
                Ok(data) => {
                    let dest = map_linux_path_to_local(&full_path, output_dir);
                    if let Some(parent) = dest.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    if let Ok(mut f) = File::create(&dest) {
                        let _ = f.write_all(&data);
                        count += 1;
                        if is_debug_mode() {
                            eprintln!("[DEBUG] Extracted: {} ({} bytes)", full_path, data.len());
                        }
                    }
                }
                Err(e) => {
                    if is_debug_mode() {
                        eprintln!("[DEBUG] Could not read {}: {}", full_path, e);
                    }
                }
            }
        }
    }

    // 3. Walk /var/log/journal/<machine-id>/*.journal{,~} — systemd-journald
    //    binary logs. On modern distros (Ubuntu 18+, RHEL 8+) this is where
    //    SSH auth actually lives; /var/log/auth.log is nearly empty when
    //    pam_sss / SSSD is in use.
    if let Ok(machines) = fs.read_dir("/var/log/journal") {
        for machine_entry in machines.flatten() {
            let machine_name = match machine_entry.file_name().as_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            if machine_name == "." || machine_name == ".." { continue; }
            match machine_entry.file_type() {
                Ok(ft) if ft.is_dir() => {}
                _ => continue,
            }
            let machine_dir = format!("/var/log/journal/{}", machine_name);
            let journal_entries = match fs.read_dir(machine_dir.as_str()) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for j in journal_entries.flatten() {
                let jname = match j.file_name().as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                };
                let jlow = jname.to_lowercase();
                if !(jlow.ends_with(".journal") || jlow.ends_with(".journal~")) {
                    continue;
                }
                match j.file_type() {
                    Ok(ft) if ft.is_regular_file() => {}
                    _ => continue,
                }
                let full_path = format!("{}/{}", machine_dir, jname);
                match fs.read(full_path.as_str()) {
                    Ok(data) => {
                        let dest = map_linux_path_to_local(&full_path, output_dir);
                        if let Some(parent) = dest.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        if let Ok(mut f) = File::create(&dest) {
                            let _ = f.write_all(&data);
                            count += 1;
                            if is_debug_mode() {
                                eprintln!("[DEBUG] Extracted journal: {} ({} bytes)", full_path, data.len());
                            }
                        }
                    }
                    Err(e) => {
                        if is_debug_mode() {
                            eprintln!("[DEBUG] Could not read journal {}: {}", full_path, e);
                        }
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Map a Linux absolute path like /var/log/auth.log to a local directory
/// structure under output_dir: output_dir/var/log/auth.log
fn map_linux_path_to_local(linux_path: &str, output_dir: &Path) -> PathBuf {
    // Strip leading / and convert to local path
    let relative = linux_path.trim_start_matches('/');
    output_dir.join(relative)
}

// -----------------------------------------------------------------------------
//  Unsafe reader wrapper to bridge borrowing and ext4-view ownership
// -----------------------------------------------------------------------------

/// This wrapper lets us pass a &mut R to ext4-view's Ext4::load() which
/// requires Box<dyn Ext4Read>. The Ext4 instance borrows our reader through
/// a raw pointer. This is safe as long as:
///   1. The Ext4 instance is dropped before the reader is dropped or moved.
///   2. No other code accesses the reader while Ext4 holds it.
/// Both conditions are guaranteed by our extract_logs_from_ext4_partition().
struct UnsafeReaderWrapper<R: Read + Seek> {
    reader: *mut R,
    partition_offset: u64,
}

// Safety: we control the lifetime and ensure single-threaded access.
unsafe impl<R: Read + Seek> Send for UnsafeReaderWrapper<R> {}
unsafe impl<R: Read + Seek> Sync for UnsafeReaderWrapper<R> {}

impl<R: Read + Seek> Ext4Read for UnsafeReaderWrapper<R> {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        let reader = unsafe { &mut *self.reader };
        reader
            .seek(SeekFrom::Start(self.partition_offset + start_byte))
            .map_err(|e| -> Box<dyn core::error::Error + Send + Sync + 'static> { Box::new(e) })?;
        reader
            .read_exact(dst)
            .map_err(|e| -> Box<dyn core::error::Error + Send + Sync + 'static> { Box::new(e) })?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
//  Recursive image scanner (same pattern as parse_image_windows)
// -----------------------------------------------------------------------------

fn scan_for_images(dir: &Path, extensions: &[&str], results: &mut Vec<String>, depth: usize) {
    if depth > 10 { return; }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
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

// -----------------------------------------------------------------------------
//  Rewrite log_filename in output CSV
// -----------------------------------------------------------------------------

/// Rewrite the log_filename column in the output CSV.
/// Replaces temp paths like ".../masstin_linux_image_extract/server.e01/logs_extracted/partition_0/var/log/auth.log"
/// or ".../masstin_image_extract/server.e01/linux_logs_extracted/partition_0/var/log/auth.log"
/// with "server.e01:partition_0:/var/log/auth.log"
pub fn rewrite_log_filenames_linux(csv_path: &str) {
    let content = match fs::read_to_string(csv_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Check for either standalone or unified temp path markers
    if !content.contains("masstin_linux_image_extract") && !content.contains("linux_logs_extracted") {
        return;
    }

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

            if !filename_field.contains("masstin_linux_image_extract") && !filename_field.contains("linux_logs_extracted") {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            let rewritten = rewrite_single_linux_filename(filename_field);
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

fn rewrite_single_linux_filename(path: &str) -> String {
    let normalized = path.replace('\\', "/");

    // Try standalone marker first: masstin_linux_image_extract/<image>/logs_extracted/partition_N/...
    if let Some(pos) = normalized.find("masstin_linux_image_extract/") {
        let after = &normalized[pos + "masstin_linux_image_extract/".len()..];
        let parts: Vec<&str> = after.splitn(2, '/').collect();
        let image_name = parts[0];
        let rest = if parts.len() > 1 { parts[1] } else { "" };
        let rest = rest.strip_prefix("logs_extracted/").unwrap_or(rest);
        let (partition, file_path) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, ""),
        };
        return format!("{}:{}:{}", image_name, partition, file_path);
    }

    // Try unified marker: masstin_image_extract/<image>/linux_logs_extracted/partition_N/...
    if let Some(pos) = normalized.find("masstin_image_extract/") {
        let after = &normalized[pos + "masstin_image_extract/".len()..];
        let parts: Vec<&str> = after.splitn(2, '/').collect();
        let image_name = parts[0];
        let rest = if parts.len() > 1 { parts[1] } else { "" };
        let rest = rest.strip_prefix("linux_logs_extracted/").unwrap_or(rest);
        let (partition, file_path) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, ""),
        };
        return format!("{}:{}:{}", image_name, partition, file_path);
    }

    path.to_string()
}
