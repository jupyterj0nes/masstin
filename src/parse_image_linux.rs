// -----------------------------------------------------------------------------
//  Forensic image parser for Linux logs
//  Opens E01/dd/VMDK images, finds ext4/ext3/ext2 and XFS volumes (as
//  partitions or LVM logical volumes), extracts log
//  files (auth.log, secure, messages, audit.log, utmp, wtmp, btmp, lastlog,
//  hostname, dpkg.log) to a temp directory, then delegates to parse_linux().
// -----------------------------------------------------------------------------

use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use ext4_view::{Ext4, Ext4Read};
use fs_core::BlockRead;
use fs_xfs::Filesystem as XfsFilesystem;
use std::sync::{Arc, Mutex};
use crate::parse::is_debug_mode;
use crate::parse_linux::parse_linux;

/// GPT partition type GUID for Linux LVM
/// E6D6D379-F507-44C2-A23C-238F2A3DF928 in mixed-endian encoding
const GPT_LINUX_LVM_GUID: [u8; 16] = [
    0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44,
    0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28,
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

/// The file systems a Linux volume can be in, as masstin reads them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinuxFs {
    /// ext2 / ext3 / ext4, through ext4-view
    Ext4,
    /// XFS (what RHEL, Rocky, Alma and Oracle Linux install by default), through rust-fs-xfs
    Xfs,
}

impl LinuxFs {
    pub fn label(self) -> &'static str {
        match self {
            LinuxFs::Ext4 => "ext4",
            LinuxFs::Xfs => "XFS",
        }
    }
}

/// What file system starts at `offset`: the ext4 magic at 0x438, or `XFSB`
/// as the first bytes of the volume.
fn sniff_linux_fs<R: Read + Seek>(reader: &mut R, offset: u64) -> Option<LinuxFs> {
    if verify_ext4_superblock(reader, offset) {
        return Some(LinuxFs::Ext4);
    }
    if reader.seek(SeekFrom::Start(offset)).is_ok() {
        let mut magic = [0u8; 4];
        if reader.read_exact(&mut magic).is_ok() && &magic == b"XFSB" {
            return Some(LinuxFs::Xfs);
        }
    }
    None
}

/// What the log extraction needs from a file system: a file by its path,
/// and a directory listing that says what each entry is. ext4 and XFS
/// both give it, so the list of logs taken is one.
trait LogTree {
    fn read_file(&self, path: &str) -> Option<Vec<u8>>;
    /// `(name, is_dir, is_regular_file)`, without `.` and `..`
    fn list_dir(&self, path: &str) -> Vec<(String, bool, bool)>;
}

impl LogTree for Ext4 {
    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        self.read(path).ok()
    }
    fn list_dir(&self, path: &str) -> Vec<(String, bool, bool)> {
        let Ok(entries) = self.read_dir(path) else { return Vec::new() };
        entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().as_str().ok()?.to_string();
                if name == "." || name == ".." {
                    return None;
                }
                let ft = e.file_type().ok()?;
                Some((name, ft.is_dir(), ft.is_regular_file()))
            })
            .collect()
    }
}

impl LogTree for XfsFilesystem {
    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        match self.read_path(path) {
            Ok(d) => Some(d),
            // /var/run is a link to /run on every current distribution
            Err(_) => path.strip_prefix("/var/run/").and_then(|rest| self.read_path(&format!("/run/{}", rest)).ok()),
        }
    }
    fn list_dir(&self, path: &str) -> Vec<(String, bool, bool)> {
        let Ok(entries) = self.list_path(path) else { return Vec::new() };
        entries
            .into_iter()
            .filter_map(|e| {
                let name = String::from_utf8_lossy(&e.name).to_string();
                if name == "." || name == ".." {
                    return None;
                }
                let inode = self.read_inode(e.ino).ok()?;
                Some((name, inode.is_dir(), inode.is_regular_file()))
            })
            .collect()
    }
}

/// Write one extracted file under `output_dir`, mirroring its Linux path.
fn save_extracted(linux_path: &str, data: &[u8], output_dir: &Path) -> bool {
    let dest = map_linux_path_to_local(linux_path, output_dir);
    if let Some(parent) = dest.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match File::create(&dest).and_then(|mut f| f.write_all(data)) {
        Ok(()) => {
            if is_debug_mode() {
                eprintln!("[DEBUG] Extracted: {} ({} bytes)", linux_path, data.len());
            }
            true
        }
        Err(_) => false,
    }
}

/// The logs masstin takes from a Linux root: the exact files, what matches
/// the known names under /var/log and /var/log/audit, and journald's
/// binary journals (on modern distributions SSH authentication lives
/// there; auth.log is nearly empty under pam_sss / SSSD).
fn extract_logs_from_tree(tree: &dyn LogTree, output_dir: &Path) -> usize {
    let mut count = 0;
    for path in EXACT_FILES {
        if let Some(data) = tree.read_file(path) {
            if save_extracted(path, &data, output_dir) {
                count += 1;
            }
        }
    }
    for log_dir in LOG_DIRS {
        for (name, _, is_file) in tree.list_dir(log_dir) {
            if !is_file {
                continue;
            }
            let lower = name.to_lowercase();
            let wanted = LOG_PREFIXES.iter().any(|p| lower.starts_with(&p.to_lowercase())) || lower == "wtmp" || lower == "btmp" || lower == "lastlog";
            if !wanted {
                continue;
            }
            let full = format!("{}/{}", log_dir, name);
            match tree.read_file(&full) {
                Some(data) => {
                    if save_extracted(&full, &data, output_dir) {
                        count += 1;
                    }
                }
                None => {
                    if is_debug_mode() {
                        eprintln!("[DEBUG] Could not read {}", full);
                    }
                }
            }
        }
    }
    for (machine, is_dir, _) in tree.list_dir("/var/log/journal") {
        if !is_dir {
            continue;
        }
        let machine_dir = format!("/var/log/journal/{}", machine);
        for (jname, _, is_file) in tree.list_dir(&machine_dir) {
            let jlow = jname.to_lowercase();
            if !is_file || !(jlow.ends_with(".journal") || jlow.ends_with(".journal~")) {
                continue;
            }
            let full = format!("{}/{}", machine_dir, jname);
            if let Some(data) = tree.read_file(&full) {
                if save_extracted(&full, &data, output_dir) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// The XFS driver wants a shared block device that answers positioned
/// reads: the same raw-pointer bridge as the ext4 wrapper below, with a
/// lock around each seek-and-read. The `Filesystem` that holds it is
/// dropped before `extract_logs_from_xfs_partition` returns, so the
/// pointer never outlives the reader it points to.
struct PtrBlockDevice<R: Read + Seek> {
    reader: Mutex<*mut R>,
    offset: u64,
    size: u64,
}

// Safety: single owner of the pointer for the life of the Filesystem, every
// access under the mutex, dropped before the borrowed reader moves.
unsafe impl<R: Read + Seek> Send for PtrBlockDevice<R> {}
unsafe impl<R: Read + Seek> Sync for PtrBlockDevice<R> {}

impl<R: Read + Seek> BlockRead for PtrBlockDevice<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        let mut guard = self.reader.lock().map_err(|_| fs_core::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "reader lock poisoned")))?;
        let reader = unsafe { &mut **guard };
        reader.seek(SeekFrom::Start(self.offset + offset))?;
        reader.read_exact(buf)?;
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.size
    }
}

/// Extract the logs of an XFS volume that starts at `partition_offset`.
fn extract_logs_from_xfs_partition<R: Read + Seek + 'static>(reader: &mut R, partition_offset: u64, output_dir: &Path) -> Result<usize, String> {
    let end = reader.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let size = end.saturating_sub(partition_offset);
    let device: Arc<dyn BlockRead> = Arc::new(PtrBlockDevice { reader: Mutex::new(reader as *mut R), offset: partition_offset, size });
    let fs = XfsFilesystem::mount(device).map_err(|e| format!("Cannot mount XFS volume: {}", e))?;
    let count = extract_logs_from_tree(&fs, output_dir);
    drop(fs);
    Ok(count)
}

/// One Linux volume, whatever it is in.
fn extract_logs_from_linux_partition<R: Read + Seek + 'static>(reader: &mut R, partition_offset: u64, kind: LinuxFs, output_dir: &Path) -> Result<usize, String> {
    match kind {
        LinuxFs::Ext4 => extract_logs_from_ext4_partition(reader, partition_offset, output_dir),
        LinuxFs::Xfs => extract_logs_from_xfs_partition(reader, partition_offset, output_dir),
    }
}

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
    let image_extensions = ["e01", "ex01", "vmdk", "vhd", "vhdx", "dd", "raw", "img", "001"];
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
            "vhd" | "vhdx" => {
                crate::banner::print_info(&format!("Image format: {} ({})", ext.to_uppercase(), image_path));
                extract_logs_from_image_vhd(image_path, &temp_dir)
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

fn extract_logs_from_image_vhd(image_path: &str, temp_dir: &Path) -> Result<PathBuf, String> {
    let (reader, image_size) = crate::vhd::open_virtual_disk(image_path)
        .map_err(|e| format!("Cannot open virtual disk: {}", e))?;
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
    crate::banner::print_phase("1", "3", "Searching for Linux partitions (ext4, XFS)...");

    let partitions = find_linux_partitions(reader, image_size)?;

    if partitions.is_empty() {
        return Err("No ext4/ext3/ext2 or XFS partitions found in image".to_string());
    }

    let kinds: Vec<&str> = partitions.iter().map(|(_, k)| k.label()).collect();
    crate::banner::print_phase_result(&format!("{} Linux partition(s) found ({})", partitions.len(), kinds.join(", ")));

    let logs_output_dir = temp_dir.join("logs_extracted");
    let _ = fs::create_dir_all(&logs_output_dir);
    let mut total_files = 0;

    for (i, (partition_offset, kind)) in partitions.iter().enumerate() {
        crate::banner::print_info(&format!(
            "Partition {} ({}) at offset {:#x} ({:.2} GB)",
            i, kind.label(), partition_offset,
            *partition_offset as f64 / 1_073_741_824.0
        ));

        let partition_dir = logs_output_dir.join(format!("partition_{}", i));
        let _ = fs::create_dir_all(&partition_dir);

        match extract_logs_from_linux_partition(reader, *partition_offset, *kind, &partition_dir) {
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
        return Err("No Linux log files found in any partition (ext4, XFS or LVM)".to_string());
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

        // ext4 or XFS?
        let kind = match sniff_linux_fs(&mut olv, 0) {
            Some(k) => k,
            None => {
                crate::banner::print_info("    Not ext4 or XFS (swap or a data volume?), skipping");
                continue;
            }
        };

        crate::banner::print_info(&format!("    {} confirmed — extracting logs...", kind.label()));

        // Dump LV to temp file so we can pass it to the volume reader
        let tmp_path = std::env::temp_dir().join(format!("masstin_lvm_{}_{}.raw", lvm_index, lv_name));
        {
            if olv.seek(SeekFrom::Start(0)).is_err() { continue; }
            let mut tmp_file = match File::create(&tmp_path) { Ok(f) => f, Err(_) => continue };
            // on the heap: a 1 MiB array on the stack overflowed the main thread on Windows
            let mut buf = vec![0u8; 1 << 20];
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
        match extract_logs_from_linux_partition(&mut tmp_file, 0, kind, &partition_dir) {
            Ok(count) if count > 0 => {
                total += count;
                crate::banner::print_info(&format!("    {} log files extracted from LV '{}'", count, lv_name));
            }
            Ok(_) => {
                crate::banner::print_info(&format!("    No log files found in LV '{}'", lv_name));
            }
            Err(e) => {
                if is_debug_mode() {
                    eprintln!("[DEBUG] LV '{}' {} error: {}", lv_name, kind.label(), e);
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
) -> Result<Vec<(u64, LinuxFs)>, String> {
    find_linux_partitions(reader, image_size)
}

/// Public wrapper for the LVM partitions (MBR 0x8E, GPT LVM GUID) of an image
pub fn find_lvm_partitions_public<R: Read + Seek>(reader: &mut R) -> Vec<u64> {
    find_lvm_partitions(reader)
}

/// Public wrapper: every logical volume of an LVM partition that holds ext4
/// or XFS, its logs extracted under `output_dir/lvm_<i>_lv_<name>`.
pub fn extract_linux_logs_from_lvm<R: Read + Seek + 'static>(reader: &mut R, lvm_offset: u64, lvm_index: usize, output_dir: &Path) -> usize {
    let _ = std::fs::create_dir_all(output_dir);
    extract_logs_from_lvm(reader, lvm_offset, lvm_index, output_dir)
}

/// Public wrapper for extracting Linux logs from a single volume (ext4 or XFS)
pub fn extract_linux_logs_from_partition<R: Read + Seek + 'static>(
    reader: &mut R,
    partition_offset: u64,
    kind: LinuxFs,
    output_dir: &Path,
    partition_index: usize,
) -> Result<usize, String> {
    let partition_dir = output_dir.join(format!("partition_{}", partition_index));
    let _ = std::fs::create_dir_all(&partition_dir);
    extract_logs_from_linux_partition(reader, partition_offset, kind, &partition_dir)
}

fn find_linux_partitions<R: Read + Seek>(
    reader: &mut R,
    _image_size: u64,
) -> Result<Vec<(u64, LinuxFs)>, String> {
    let mut partitions: Vec<(u64, LinuxFs)> = Vec::new();

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

                    // whatever the type GUID says, the superblock decides (ext4 or XFS)
                    if let Some(kind) = sniff_linux_fs(reader, partition_byte_offset) {
                        if is_debug_mode() {
                            eprintln!("[DEBUG] GPT partition {} at LBA {} (offset {:#x}) -- {} confirmed",
                                i, first_lba, partition_byte_offset, kind.label());
                        }
                        partitions.push((partition_byte_offset, kind));
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
                    if let Some(kind) = sniff_linux_fs(reader, offset) {
                        if is_debug_mode() {
                            eprintln!("[DEBUG] MBR partition {} at LBA {} (offset {:#x}) -- {} confirmed",
                                i, lba_start, offset, kind.label());
                        }
                        partitions.push((offset, kind));
                    }
                }
            }
        }
    }

    // Fallback: the image is a bare volume (no partition table)
    if partitions.is_empty() {
        if let Some(kind) = sniff_linux_fs(reader, 0) {
            if is_debug_mode() {
                eprintln!("[DEBUG] {} superblock found at offset 0 (partition image)", kind.label());
            }
            partitions.push((0, kind));
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
    let count = extract_logs_from_tree(&fs, output_dir);
    drop(fs);
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
    if !content.contains("masstin_linux_image_extract") && !content.contains("linux_logs_extracted") {
        return;
    }
    let mut lines = content.lines();
    let Some(header) = lines.next() else { return };
    // the column by its name: the row carries a tail after `log_filename`
    let Some(col) = header.split(',').position(|h| h == "log_filename") else { return };
    let mut output = String::with_capacity(content.len());
    output.push_str(header);
    output.push('\n');
    for line in lines {
        let mut fields = split_csv_line(line);
        let renamed = match fields.get(col) {
            Some(f) if f.contains("masstin_linux_image_extract") || f.contains("linux_logs_extracted") => Some(crate::csv_out::q(&crate::parse::display_source(f))),
            _ => None,
        };
        match renamed {
            Some(name) => {
                fields[col] = name;
                output.push_str(&fields.join(","));
            }
            None => output.push_str(line),
        }
        output.push('\n');
    }
    let _ = fs::write(csv_path, output);
}

/// A CSV line as its fields, each kept exactly as written (quotes and
/// all), so a line put back together is the line it was.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ',' if !quoted => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

#[cfg(test)]
mod rewrite_tests {
    use super::*;

    #[test]
    fn the_filename_column_is_found_by_name_and_the_rest_kept() {
        let line = r#"2026-11-03 10:43:56,lab-xfs,LOGON,ACCEPT,SSH,vagrant,"",,10.10.0.50,"","",1200,"sshd, publickey",/tmp/masstin_image_extract/0_srv.e01/linux_logs_extracted/partition_0/var/log/secure,,,,,"#;
        let fields = split_csv_line(line);
        assert_eq!(fields.len(), 19);
        assert_eq!(fields[12], r#""sshd, publickey""#);
        assert_eq!(fields.join(","), line);
        let dir = std::env::temp_dir().join(format!("masstin_rewrite_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.csv");
        std::fs::write(&p, format!("{}\n{}\n", crate::csv_out::HEADER, line)).unwrap();
        rewrite_log_filenames_linux(p.to_str().unwrap());
        let back = std::fs::read_to_string(&p).unwrap();
        let row = back.lines().nth(1).unwrap();
        let fields = split_csv_line(row);
        assert_eq!(fields[13], "srv.e01:partition_0:/var/log/secure");
        assert_eq!(fields[12], r#""sshd, publickey""#);
        assert_eq!(fields[18], "");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod xfs_tests {
    use super::*;
    use fs_core::{BlockDevice, FileDevice};

    const SECURE: &[u8] = b"Nov  3 10:43:56 lab-xfs sshd[1200]: Accepted publickey for vagrant from 10.10.0.50 port 51234 ssh2: ED25519 SHA256:abc\nNov  3 10:44:01 lab-xfs sshd[1200]: pam_unix(sshd:session): session opened for user vagrant by (uid=0)\n";

    /// An XFS volume made by the driver itself, holding the files masstin
    /// looks for and one it does not: the extraction takes exactly those.
    #[test]
    fn xfs_volume_gives_its_logs() {
        let dir = std::env::temp_dir().join(format!("masstin_xfs_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let img = dir.join("vol.img");
        // the driver's formatter wants 300 MiB at least; the file stays sparse
        File::create(&img).unwrap().set_len(320 << 20).unwrap();
        {
            let dev = Arc::new(FileDevice::open_rw(&img).unwrap());
            fs_xfs::mkfs::format(&*dev, &fs_xfs::mkfs::Options::default()).expect("format");
            let fsx = XfsFilesystem::mount_rw(dev as Arc<dyn BlockDevice>).expect("mount_rw");
            let root = fsx.lookup_path("/").unwrap().ino;
            let mkdir = |parent: u64, name: &str| fsx.create_directory(parent, name.as_bytes(), 0o40755).expect("dir").0;
            let write = |parent: u64, name: &str, data: &[u8]| {
                let (ino, _) = fsx.create_file(parent, name.as_bytes(), 0o100644).expect("file");
                fsx.write_into_empty_file(ino, data).expect("write");
            };
            let etc = mkdir(root, "etc");
            write(etc, "hostname", b"lab-xfs\n");
            let var = mkdir(root, "var");
            let log = mkdir(var, "log");
            write(log, "secure", SECURE);
            write(log, "wtmp", &[0u8; 384]);
            write(log, "Xorg.0.log", b"not a login log\n");
            let audit = mkdir(log, "audit");
            write(audit, "audit.log", b"type=USER_LOGIN msg=audit(1700000000.000:1): pid=1 uid=0 auid=1000 ses=1 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=success'\n");
            let journal = mkdir(log, "journal");
            let machine = mkdir(journal, "0123456789abcdef0123456789abcdef");
            write(machine, "system.journal", b"LPKSHHRH");
            fsx.unmount().expect("unmount");
        }
        let out = dir.join("out");
        let mut reader = File::open(&img).unwrap();
        assert_eq!(sniff_linux_fs(&mut reader, 0), Some(LinuxFs::Xfs));
        assert_eq!(find_linux_partitions(&mut reader, 0).unwrap(), vec![(0, LinuxFs::Xfs)]);
        let n = extract_logs_from_xfs_partition(&mut reader, 0, &out).expect("extract");
        assert_eq!(fs::read_to_string(out.join("etc/hostname")).unwrap().trim(), "lab-xfs");
        assert_eq!(fs::read(out.join("var/log/secure")).unwrap(), SECURE);
        assert!(out.join("var/log/wtmp").is_file());
        assert!(out.join("var/log/audit/audit.log").is_file());
        assert!(out.join("var/log/journal/0123456789abcdef0123456789abcdef/system.journal").is_file());
        assert!(!out.join("var/log/Xorg.0.log").exists());
        // hostname, wtmp (as an exact file and again from the listing), secure, audit.log, the journal
        assert_eq!(n, 6);
        drop(reader);
        let _ = fs::remove_dir_all(&dir);
    }
}
