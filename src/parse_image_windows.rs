// -----------------------------------------------------------------------------
//  Forensic image parser for Windows EVTX
//  Opens E01/dd images, parses NTFS, extracts EVTX files to temp dir,
//  then delegates to the existing parse_events() function.
// -----------------------------------------------------------------------------

use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vshadow::VssVolume;
use crate::parse::{parse_events, is_debug_mode};

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const EVTX_LOGS_PATH: &[&str] = &["Windows", "System32", "winevt", "Logs"];

/// Main entry point: parse EVTX files from a forensic disk image (E01 or dd/raw)
pub fn parse_image_windows(files: &[String], output: Option<&String>) {
    let start_time = std::time::Instant::now();

    crate::banner::print_phase("1", "3", "Opening forensic image...");

    for image_path in files {
        let ext = Path::new(image_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Create temp dir for extracted EVTX files
        let temp_dir = std::env::temp_dir().join("masstin_image_extract");
        let _ = fs::create_dir_all(&temp_dir);

        let evtx_dir = match ext.as_str() {
            "e01" | "ex01" => {
                crate::banner::print_info(&format!("Image format: E01 ({})", image_path));
                extract_evtx_from_image_ewf(image_path, &temp_dir)
            }
            "dd" | "raw" | "img" | "001" => {
                crate::banner::print_info(&format!("Image format: raw/dd ({})", image_path));
                extract_evtx_from_image_raw(image_path, &temp_dir)
            }
            _ => {
                // Try raw first, fall back to EWF
                crate::banner::print_info(&format!("Unknown extension, trying raw then E01 ({})", image_path));
                extract_evtx_from_image_raw(image_path, &temp_dir)
                    .or_else(|_| extract_evtx_from_image_ewf(image_path, &temp_dir))
            }
        };

        match evtx_dir {
            Ok(dir) => {
                let dir_str = dir.to_string_lossy().to_string();
                crate::banner::print_phase_result(&format!(
                    "EVTX files extracted to temp directory"
                ));

                // Phase 2+3: delegate to existing parse_events
                let dirs = vec![dir_str];
                let empty_files: Vec<String> = vec![];
                parse_events(&empty_files, &dirs, output);
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to process image {}: {}", image_path, e);
            }
        }

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
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
    crate::banner::print_phase("1", "3", "Searching for NTFS partitions...");

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

                    match vss.store_reader(&mut offset_reader, s) {
                        Ok(mut store_reader) => {
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
