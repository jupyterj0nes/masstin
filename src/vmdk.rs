// -----------------------------------------------------------------------------
//  VMDK reader — implements Read + Seek for VMware VMDK disk images
//  Supports: monolithic sparse, monolithic flat, split sparse, split flat
// -----------------------------------------------------------------------------

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use flate2::read::ZlibDecoder;

const SECTOR_SIZE: u64 = 512;
const SPARSE_MAGIC: u32 = 0x564D444B; // "KDMV"
const GD_AT_END: u64 = 0xFFFFFFFFFFFFFFFF;

// -----------------------------------------------------------------------------
//  Sparse header (parsed from first 512 bytes of a sparse extent)
// -----------------------------------------------------------------------------
#[derive(Debug, Clone)]
struct SparseHeader {
    version: u32,
    capacity: u64,          // max sectors in this extent
    grain_size: u64,        // sectors per grain (power of 2)
    num_gte_per_gt: u32,    // grain table entries per grain table (typically 512)
    gd_offset: u64,         // primary grain directory offset in sectors
    compressed: bool,       // true for streamOptimized (compressed grains)
}

// -----------------------------------------------------------------------------
//  Extent types
// -----------------------------------------------------------------------------
enum ExtentData {
    Flat {
        file: File,
        file_offset: u64, // byte offset into the flat file where data starts
    },
    Sparse {
        file: File,
        header: SparseHeader,
        grain_directory: Vec<u32>,  // GD entries (sector offsets to grain tables)
        grain_table_cache: std::collections::HashMap<u32, Vec<u32>>, // gd_index -> grain table
        grain_data_cache: std::collections::HashMap<u64, Vec<u8>>,  // grain_index -> decompressed data
    },
}

struct Extent {
    data: ExtentData,
    size_bytes: u64, // total bytes this extent covers
}

// -----------------------------------------------------------------------------
//  Public VmdkReader
// -----------------------------------------------------------------------------
pub struct VmdkReader {
    extents: Vec<Extent>,
    total_size: u64,
    position: u64,
}

impl VmdkReader {
    /// Open a VMDK file (descriptor or monolithic sparse).
    pub fn open(path: &str) -> Result<Self, String> {
        let vmdk_path = Path::new(path);
        let base_dir = vmdk_path.parent().unwrap_or(Path::new("."));

        // Read first 4 bytes to determine type
        let mut file = File::open(path)
            .map_err(|e| format!("Cannot open VMDK file '{}': {}", path, e))?;

        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf)
            .map_err(|e| format!("Cannot read VMDK header: {}", e))?;

        let magic = u32::from_le_bytes(magic_buf);

        if magic == SPARSE_MAGIC {
            // Monolithic sparse — header + data in same file
            drop(file);
            let extent = Self::open_sparse_extent(path)?;
            let size = extent.size_bytes;
            Ok(VmdkReader {
                extents: vec![extent],
                total_size: size,
                position: 0,
            })
        } else {
            // Try to read as text descriptor (limited to 64KB — descriptors are small text files)
            drop(file);
            let mut file = File::open(path)
                .map_err(|e| format!("Cannot open VMDK '{}': {}", path, e))?;
            let mut buf = vec![0u8; 65536];
            let n = file.read(&mut buf).map_err(|e| format!("Cannot read VMDK: {}", e))?;
            let text = String::from_utf8_lossy(&buf[..n]);

            if text.contains("# Disk DescriptorFile") || text.contains("createType") {
                Self::open_from_descriptor(&text, base_dir)
            } else {
                // Not a descriptor — treat as raw/flat image
                drop(file);
                let file = File::open(path)
                    .map_err(|e| format!("Cannot open raw VMDK: {}", e))?;
                let size = file.metadata().map(|m| m.len()).unwrap_or(0);
                Ok(VmdkReader {
                    extents: vec![Extent {
                        data: ExtentData::Flat { file, file_offset: 0 },
                        size_bytes: size,
                    }],
                    total_size: size,
                    position: 0,
                })
            }
        }
    }

    /// Total addressable size of the virtual disk in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Cheap size probe: returns the declared virtual disk size without
    /// opening extent files or validating sparse headers. Used for the
    /// header display so descriptor-based VMDKs don't report ~1 KB.
    /// Falls back to None on parse errors — caller should fall back to
    /// fs::metadata().len().
    pub fn probe_size(path: &str) -> Option<u64> {
        let mut file = File::open(path).ok()?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).ok()?;
        let magic = u32::from_le_bytes(magic_buf);

        if magic == SPARSE_MAGIC {
            // Monolithic sparse — size is in the header capacity field
            file.seek(SeekFrom::Start(0)).ok()?;
            let h = Self::read_sparse_header_at_current(&mut file).ok()?;
            return Some(h.capacity * SECTOR_SIZE);
        }

        // Descriptor: read first 64 KB as text and sum extent sector counts
        drop(file);
        let mut file = File::open(path).ok()?;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        if !text.contains("# Disk DescriptorFile") && !text.contains("createType") {
            return None;
        }
        let mut total_sectors: u64 = 0;
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("RW ") && !line.starts_with("RDONLY ") && !line.starts_with("NOACCESS ") {
                continue;
            }
            if let Ok(parts) = Self::parse_extent_line(line) {
                total_sectors = total_sectors.saturating_add(parts.sectors);
            }
        }
        if total_sectors == 0 { None } else { Some(total_sectors * SECTOR_SIZE) }
    }

    // -------------------------------------------------------------------------
    //  Descriptor parsing
    // -------------------------------------------------------------------------
    fn open_from_descriptor(descriptor: &str, base_dir: &Path) -> Result<Self, String> {
        let mut extents = Vec::new();
        let mut total_size: u64 = 0;

        for line in descriptor.lines() {
            let line = line.trim();
            // Extent lines look like:
            //   RW 41943040 SPARSE "disk-s001.vmdk"
            //   RW 41943040 FLAT "disk-flat.vmdk" 0
            if !line.starts_with("RW ") && !line.starts_with("RDONLY ") && !line.starts_with("NOACCESS ") {
                continue;
            }

            let parts = Self::parse_extent_line(line)?;
            let sectors: u64 = parts.sectors;
            let extent_type = parts.extent_type.as_str();
            let filename = &parts.filename;
            let flat_offset = parts.flat_offset;

            let extent_path = base_dir.join(filename);
            let extent_path_str = extent_path.to_string_lossy().to_string();

            let extent = match extent_type.to_uppercase().as_str() {
                "FLAT" | "VMFS" | "VMFSRAW" | "VMFSRDM" => {
                    let f = match File::open(&extent_path) {
                        Ok(f) => f,
                        Err(_) => {
                            // Try .filepart fallback (incomplete SFTP uploads)
                            let filepart_path = format!("{}.filepart", extent_path_str);
                            match File::open(&filepart_path) {
                                Ok(f) => {
                                    eprintln!("        {}",
                                        console::style(format!(
                                            "WARNING: Using incomplete upload '{}.filepart' (SFTP transfer may have lacked rename permission)",
                                            filename
                                        )).yellow()
                                    );
                                    f
                                }
                                Err(_) => {
                                    return Err(format!("Incomplete VMDK: flat extent '{}' not found (only descriptor was collected)", filename));
                                }
                            }
                        }
                    };
                    Extent {
                        data: ExtentData::Flat {
                            file: f,
                            file_offset: flat_offset * SECTOR_SIZE,
                        },
                        size_bytes: sectors * SECTOR_SIZE,
                    }
                }
                "SPARSE" | "VMFSSPARSE" => {
                    Self::open_sparse_extent(&extent_path_str)?
                }
                "ZERO" => {
                    // Zero extent — reads return zeros, no backing file
                    Extent {
                        data: ExtentData::Flat {
                            file: File::open(&extent_path).unwrap_or_else(|_| {
                                // Zero extents don't need a file — create a dummy
                                File::open(std::env::temp_dir().join("__masstin_zero")).unwrap_or_else(|_| {
                                    File::open("/dev/null").unwrap()
                                })
                            }),
                            file_offset: 0,
                        },
                        size_bytes: sectors * SECTOR_SIZE,
                    }
                }
                _ => {
                    return Err(format!("Unsupported extent type: {}", extent_type));
                }
            };

            total_size += extent.size_bytes;
            extents.push(extent);
        }

        if extents.is_empty() {
            return Err("No extent lines found in VMDK descriptor".to_string());
        }

        Ok(VmdkReader {
            extents,
            total_size,
            position: 0,
        })
    }

    // -------------------------------------------------------------------------
    //  Parse a single extent line
    // -------------------------------------------------------------------------
    fn parse_extent_line(line: &str) -> Result<ExtentLineParts, String> {
        // Format: ACCESS SECTORS TYPE "FILENAME" [OFFSET]
        // e.g.:   RW 41943040 SPARSE "disk-s001.vmdk"
        //         RW 41943040 FLAT "disk-flat.vmdk" 0

        let mut chars = line.chars().peekable();
        let mut tokens: Vec<String> = Vec::new();

        loop {
            // skip whitespace
            while chars.peek().map_or(false, |c| c.is_whitespace()) {
                chars.next();
            }
            if chars.peek().is_none() {
                break;
            }

            if chars.peek() == Some(&'"') {
                // quoted token
                chars.next(); // consume opening quote
                let mut tok = String::new();
                for c in chars.by_ref() {
                    if c == '"' {
                        break;
                    }
                    tok.push(c);
                }
                tokens.push(tok);
            } else {
                let mut tok = String::new();
                while chars.peek().map_or(false, |c| !c.is_whitespace()) {
                    tok.push(chars.next().unwrap());
                }
                tokens.push(tok);
            }
        }

        // tokens: [access, sectors, type, filename, (optional offset)]
        if tokens.len() < 4 {
            return Err(format!("Malformed extent line: {}", line));
        }

        let sectors: u64 = tokens[1].parse()
            .map_err(|_| format!("Invalid sector count in extent line: {}", line))?;
        let extent_type = tokens[2].clone();
        let filename = tokens[3].clone();
        let flat_offset: u64 = if tokens.len() > 4 {
            tokens[4].parse().unwrap_or(0)
        } else {
            0
        };

        Ok(ExtentLineParts {
            sectors,
            extent_type,
            filename,
            flat_offset,
        })
    }

    // -------------------------------------------------------------------------
    //  Open and parse a sparse extent file
    // -------------------------------------------------------------------------
    fn open_sparse_extent(path: &str) -> Result<Extent, String> {
        let mut file = File::open(path)
            .map_err(|e| format!("Cannot open sparse extent '{}': {}", path, e))?;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Cannot seek to start: {}", e))?;
        let mut header = Self::read_sparse_header_at_current(&mut file)?;

        // For streamOptimized: read footer to get real gd_offset
        if header.gd_offset == GD_AT_END || header.gd_offset == 0 {
            if !header.compressed && header.capacity > 0 {
                return Err("Grain directory at end of file but not compressed — unsupported format".to_string());
            }
            // Footer (copy of header with correct gd_offset) is near the end of the file.
            // Layout: ... | footer marker (512) | footer/header (512) | EOS marker (512) |
            // Try reading at -1024 first (most common), then -1536
            let file_size = file.seek(SeekFrom::End(0))
                .map_err(|e| format!("Cannot seek to end: {}", e))?;

            // Declared capacity from the first header — lets us spot
            // truncated files (declared > on-disk) and report it cleanly.
            let declared_bytes = header.capacity.saturating_mul(SECTOR_SIZE);

            let mut footer_header = None;
            let mut debug_info = format!("file_size={}", file_size);
            for offset_from_end in &[1024u64, 1536, 2048, 512] {
                let pos = file_size.saturating_sub(*offset_from_end);
                if file.seek(SeekFrom::Start(pos)).is_err() { continue; }
                if let Ok(h) = Self::read_sparse_header_at_current(&mut file) {
                    if h.gd_offset != GD_AT_END && h.gd_offset != 0 && h.capacity > 0 {
                        footer_header = Some(h);
                        break;
                    }
                    debug_info.push_str(&format!(", at-{}:gd={}", offset_from_end, h.gd_offset));
                } else {
                    debug_info.push_str(&format!(", at-{}:no_magic", offset_from_end));
                }
            }

            let footer_header = footer_header.ok_or_else(|| {
                let gb = |b: u64| b as f64 / 1_073_741_824.0;
                if declared_bytes > 0 && file_size < declared_bytes {
                    format!(
                        "streamOptimized VMDK truncated: declared {:.1} GB, only {:.1} GB on disk — footer missing ({})",
                        gb(declared_bytes), gb(file_size), debug_info
                    )
                } else {
                    format!(
                        "streamOptimized VMDK: no valid footer found (declared {:.1} GB, file {:.1} GB, {})",
                        gb(declared_bytes), gb(file_size), debug_info
                    )
                }
            })?;
            if footer_header.gd_offset != GD_AT_END && footer_header.gd_offset != 0 {
                header.gd_offset = footer_header.gd_offset;
            } else {
                return Err("streamOptimized VMDK: footer does not contain valid grain directory offset".to_string());
            }
        }

        // Load grain directory into memory
        let num_gd_entries = Self::gd_entry_count(&header);
        let gd_byte_offset = header.gd_offset * SECTOR_SIZE;

        file.seek(SeekFrom::Start(gd_byte_offset))
            .map_err(|e| format!("Cannot seek to grain directory: {}", e))?;

        let mut grain_directory = vec![0u32; num_gd_entries];
        let mut gd_buf = vec![0u8; num_gd_entries * 4];
        file.read_exact(&mut gd_buf)
            .map_err(|e| format!("Cannot read grain directory: {}", e))?;

        for i in 0..num_gd_entries {
            grain_directory[i] = u32::from_le_bytes([
                gd_buf[i * 4],
                gd_buf[i * 4 + 1],
                gd_buf[i * 4 + 2],
                gd_buf[i * 4 + 3],
            ]);
        }

        let size_bytes = header.capacity * SECTOR_SIZE;

        Ok(Extent {
            data: ExtentData::Sparse {
                file,
                header,
                grain_directory,
                grain_table_cache: std::collections::HashMap::new(),
                grain_data_cache: std::collections::HashMap::new(),
            },
            size_bytes,
        })
    }

    // -------------------------------------------------------------------------
    //  Read the 512-byte sparse header
    // -------------------------------------------------------------------------
    fn read_sparse_header(file: &mut File) -> Result<SparseHeader, String> {
        Self::read_sparse_header_at_current(file)
    }

    /// Read sparse header from current file position (does NOT seek to 0)
    fn read_sparse_header_at_current(file: &mut File) -> Result<SparseHeader, String> {
        let mut buf = [0u8; 72]; // we only need the first 72 bytes
        file.read_exact(&mut buf)
            .map_err(|e| format!("Cannot read sparse header: {}", e))?;

        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != SPARSE_MAGIC {
            return Err("Not a sparse VMDK (bad magic)".to_string());
        }

        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let flags = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let capacity = u64::from_le_bytes([
            buf[12], buf[13], buf[14], buf[15],
            buf[16], buf[17], buf[18], buf[19],
        ]);
        let grain_size = u64::from_le_bytes([
            buf[20], buf[21], buf[22], buf[23],
            buf[24], buf[25], buf[26], buf[27],
        ]);
        let num_gte_per_gt = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let gd_offset = u64::from_le_bytes([
            buf[56], buf[57], buf[58], buf[59],
            buf[60], buf[61], buf[62], buf[63],
        ]);

        let compressed = (flags & 0x10000) != 0;

        Ok(SparseHeader {
            version,
            capacity,
            grain_size,
            num_gte_per_gt,
            gd_offset,
            compressed,
        })
    }

    /// Number of entries in the grain directory.
    fn gd_entry_count(header: &SparseHeader) -> usize {
        let grains_per_gt = header.num_gte_per_gt as u64;
        let sectors_per_gt = grains_per_gt * header.grain_size;
        if sectors_per_gt == 0 {
            return 0;
        }
        ((header.capacity + sectors_per_gt - 1) / sectors_per_gt) as usize
    }

    // -------------------------------------------------------------------------
    //  Find which extent a global byte offset falls in
    // -------------------------------------------------------------------------
    fn find_extent(&self, global_offset: u64) -> Option<(usize, u64)> {
        let mut cumulative: u64 = 0;
        for (i, ext) in self.extents.iter().enumerate() {
            if global_offset < cumulative + ext.size_bytes {
                return Some((i, global_offset - cumulative));
            }
            cumulative += ext.size_bytes;
        }
        None
    }

    // -------------------------------------------------------------------------
    //  Read bytes from a flat extent
    // -------------------------------------------------------------------------
    fn read_flat(file: &mut File, file_offset: u64, local_offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        file.seek(SeekFrom::Start(file_offset + local_offset))?;
        file.read(buf)
    }

    // -------------------------------------------------------------------------
    //  Read bytes from a sparse extent
    // -------------------------------------------------------------------------
    fn read_sparse(
        file: &mut File,
        header: &SparseHeader,
        grain_directory: &[u32],
        grain_table_cache: &mut std::collections::HashMap<u32, Vec<u32>>,
        grain_data_cache: &mut std::collections::HashMap<u64, Vec<u8>>,
        local_offset: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let grain_bytes = header.grain_size * SECTOR_SIZE;
        if grain_bytes == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Zero grain size"));
        }

        let extent_size = header.capacity * SECTOR_SIZE;
        if local_offset >= extent_size {
            return Ok(0);
        }

        let gte_per_gt = header.num_gte_per_gt as u64;
        let sector_offset = local_offset / SECTOR_SIZE;
        let grain_index = sector_offset / header.grain_size;
        let gd_index = (grain_index / gte_per_gt) as usize;
        let gt_index = (grain_index % gte_per_gt) as usize;

        // How far into this grain are we?
        let offset_in_grain = local_offset % grain_bytes;
        let bytes_left_in_grain = grain_bytes - offset_in_grain;
        let bytes_left_in_extent = extent_size - local_offset;
        let max_read = buf.len().min(bytes_left_in_grain as usize).min(bytes_left_in_extent as usize);

        if gd_index >= grain_directory.len() {
            // Beyond grain directory — return zeros
            buf[..max_read].fill(0);
            return Ok(max_read);
        }

        let gd_entry = grain_directory[gd_index];

        // Unallocated or zeroed grain directory entry
        if gd_entry == 0 || gd_entry == 1 {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }

        // Load grain table (cached)
        let gt = Self::load_grain_table(file, grain_table_cache, gd_entry, gte_per_gt as usize)?;

        if gt_index >= gt.len() {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }

        let gt_entry = gt[gt_index];

        // Unallocated or zeroed grain
        if gt_entry == 0 || gt_entry == 1 {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }

        if header.compressed {
            // StreamOptimized: grain is compressed. gt_entry points to a marker.
            // Marker: { lba: u64, size: u32, data: [u8; size] }
            // Decompress and cache the full grain, then copy the requested portion.
            if let Some(cached) = grain_data_cache.get(&grain_index) {
                let start = offset_in_grain as usize;
                let end = (start + max_read).min(cached.len());
                if start < cached.len() {
                    buf[..end - start].copy_from_slice(&cached[start..end]);
                    return Ok(end - start);
                }
                buf[..max_read].fill(0);
                return Ok(max_read);
            }

            let marker_offset = (gt_entry as u64) * SECTOR_SIZE;
            file.seek(SeekFrom::Start(marker_offset))?;
            let mut marker_buf = [0u8; 12];
            file.read_exact(&mut marker_buf)?;
            let _lba = u64::from_le_bytes(marker_buf[0..8].try_into().unwrap());
            let compressed_size = u32::from_le_bytes(marker_buf[8..12].try_into().unwrap());

            if compressed_size == 0 || compressed_size > 10_000_000 {
                // Invalid or too large — treat as zero grain
                buf[..max_read].fill(0);
                return Ok(max_read);
            }

            let mut compressed_data = vec![0u8; compressed_size as usize];
            file.read_exact(&mut compressed_data)?;

            // Decompress with zlib
            let mut decoder = ZlibDecoder::new(&compressed_data[..]);
            let grain_byte_size = (header.grain_size * SECTOR_SIZE) as usize;
            let mut decompressed = vec![0u8; grain_byte_size];
            let decompressed_len = decoder.read(&mut decompressed).unwrap_or(0);
            decompressed.truncate(decompressed_len);

            // Cache and return requested portion
            let start = offset_in_grain as usize;
            let end = (start + max_read).min(decompressed.len());
            if start < decompressed.len() {
                buf[..end - start].copy_from_slice(&decompressed[start..end]);
            } else {
                buf[..max_read].fill(0);
            }

            // Keep cache bounded (LRU-style: drop old entries if too many)
            if grain_data_cache.len() > 1024 {
                grain_data_cache.clear();
            }
            grain_data_cache.insert(grain_index, decompressed);

            Ok(if start < decompressed_len { end - start } else { max_read })
        } else {
            // Normal sparse: read raw grain data directly
            let grain_data_offset = (gt_entry as u64) * SECTOR_SIZE + offset_in_grain;
            file.seek(SeekFrom::Start(grain_data_offset))?;
            file.read(&mut buf[..max_read])
        }
    }

    // -------------------------------------------------------------------------
    //  Load a grain table, caching it
    // -------------------------------------------------------------------------
    fn load_grain_table(
        file: &mut File,
        cache: &mut std::collections::HashMap<u32, Vec<u32>>,
        gd_entry: u32,
        num_entries: usize,
    ) -> io::Result<Vec<u32>> {
        if let Some(gt) = cache.get(&gd_entry) {
            return Ok(gt.clone());
        }

        let gt_byte_offset = (gd_entry as u64) * SECTOR_SIZE;
        file.seek(SeekFrom::Start(gt_byte_offset))?;

        let mut raw = vec![0u8; num_entries * 4];
        file.read_exact(&mut raw)?;

        let mut gt = vec![0u32; num_entries];
        for i in 0..num_entries {
            gt[i] = u32::from_le_bytes([
                raw[i * 4],
                raw[i * 4 + 1],
                raw[i * 4 + 2],
                raw[i * 4 + 3],
            ]);
        }

        cache.insert(gd_entry, gt.clone());
        Ok(gt)
    }
}

// Helper for extent line parsing
struct ExtentLineParts {
    sectors: u64,
    extent_type: String,
    filename: String,
    flat_offset: u64,
}

// -----------------------------------------------------------------------------
//  Read implementation
// -----------------------------------------------------------------------------
impl Read for VmdkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }

        let (ext_idx, local_offset) = match self.find_extent(self.position) {
            Some(v) => v,
            None => return Ok(0),
        };

        let extent = &mut self.extents[ext_idx];

        // Clamp read to extent boundary
        let remaining_in_extent = extent.size_bytes - local_offset;
        let read_len = buf.len().min(remaining_in_extent as usize);

        let n = match &mut extent.data {
            ExtentData::Flat { file, file_offset } => {
                let fo = *file_offset;
                Self::read_flat(file, fo, local_offset, &mut buf[..read_len])?
            }
            ExtentData::Sparse {
                file,
                header,
                grain_directory,
                grain_table_cache,
                grain_data_cache,
            } => {
                Self::read_sparse(
                    file,
                    header,
                    grain_directory,
                    grain_table_cache,
                    grain_data_cache,
                    local_offset,
                    &mut buf[..read_len],
                )?
            }
        };

        self.position += n as u64;
        Ok(n)
    }
}

// -----------------------------------------------------------------------------
//  Seek implementation
// -----------------------------------------------------------------------------
impl Seek for VmdkReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.total_size as i64 + offset,
            SeekFrom::Current(offset) => self.position as i64 + offset,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek to a negative position",
            ));
        }

        self.position = new_pos as u64;
        Ok(self.position)
    }
}
