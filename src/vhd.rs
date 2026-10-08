//! Readers for Microsoft virtual disks: VHD (fixed and dynamic) and VHDX
//! (fixed and dynamic). Both expose the virtual disk as `Read + Seek`, the
//! same surface as `VmdkReader`, so the NTFS / ext4 walkers and the carver
//! use them unchanged.
//!
//! VHD (Connectix "conectix"): the last 512 bytes are the footer with the
//! disk type and the virtual size. A fixed VHD is the raw disk followed by
//! that footer. A dynamic VHD keeps a "cxsparse" header pointing at a block
//! allocation table (BAT) of big-endian sector numbers, one per block
//! (2 MB by default); each allocated block starts with a sector bitmap
//! whose clear bits read as zeros. Differencing disks (a parent chain) are
//! refused.
//!
//! VHDX ("vhdxfile"): two headers at 64 KB and 128 KB (the one with the
//! higher sequence number is current), two region tables at 192 KB and
//! 256 KB naming the BAT and the metadata regions, and a metadata table
//! with the block size, the logical sector size and the virtual size. The
//! BAT is an array of little-endian u64 entries, state in the low 3 bits
//! and the file offset in the upper 44 (MB-aligned); after every
//! `chunk_ratio` payload entries comes one sector-bitmap entry, which is
//! skipped. Blocks that are not present read as zeros. A disk with a parent
//! (differencing) is refused.
//!
//! Neither reader applies the VHDX log: a disk detached cleanly has an
//! empty log, and an image is read as a file, never written.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

// ───────────────────────────── VHD ─────────────────────────────

const VHD_FOOTER: usize = 512;
const VHD_FIXED: u32 = 2;
const VHD_DYNAMIC: u32 = 3;
const VHD_DIFFERENCING: u32 = 4;

enum VhdLayout {
    Fixed,
    Dynamic {
        /// absolute file offset of each block's data (after its bitmap), or
        /// None when the block was never allocated
        blocks: Vec<Option<u64>>,
        block_size: u64,
        bitmap_bytes: u64,
    },
}

pub struct VhdReader {
    file: File,
    layout: VhdLayout,
    total_size: u64,
    position: u64,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn be64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)
}

impl VhdReader {
    pub fn open(path: &str) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|e| format!("Cannot open VHD: {}", e))?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        if len < VHD_FOOTER as u64 {
            return Err("VHD too small to hold a footer".into());
        }
        let mut footer = [0u8; VHD_FOOTER];
        read_at(&mut file, len - VHD_FOOTER as u64, &mut footer).map_err(|e| e.to_string())?;
        if &footer[..8] != b"conectix" {
            // some writers leave a truncated footer (511 bytes); try the copy at the start
            read_at(&mut file, 0, &mut footer).map_err(|e| e.to_string())?;
            if &footer[..8] != b"conectix" {
                return Err("not a VHD: no conectix footer".into());
            }
        }
        let data_offset = be64(&footer, 16);
        let current_size = be64(&footer, 48);
        let disk_type = be32(&footer, 60);
        let layout = match disk_type {
            VHD_FIXED => VhdLayout::Fixed,
            VHD_DYNAMIC => {
                let mut hdr = [0u8; 1024];
                read_at(&mut file, data_offset, &mut hdr).map_err(|e| format!("dynamic header: {}", e))?;
                if &hdr[..8] != b"cxsparse" {
                    return Err("dynamic VHD without a cxsparse header".into());
                }
                let table_offset = be64(&hdr, 16);
                let max_entries = be32(&hdr, 28) as usize;
                let block_size = be32(&hdr, 32) as u64;
                if block_size == 0 || block_size % 512 != 0 {
                    return Err(format!("dynamic VHD with an invalid block size {}", block_size));
                }
                let sectors = block_size / 512;
                let bitmap_bytes = ((sectors + 7) / 8 + 511) / 512 * 512;
                if (max_entries as u64) * 4 > len {
                    return Err(format!("dynamic VHD with a BAT of {} entries in a {}-byte file", max_entries, len));
                }
                let mut bat = vec![0u8; max_entries * 4];
                read_at(&mut file, table_offset, &mut bat).map_err(|e| format!("BAT: {}", e))?;
                let blocks = (0..max_entries)
                    .map(|i| {
                        let s = be32(&bat, i * 4);
                        if s == 0xFFFF_FFFF { None } else { Some(s as u64 * 512) }
                    })
                    .collect();
                VhdLayout::Dynamic { blocks, block_size, bitmap_bytes }
            }
            VHD_DIFFERENCING => return Err("differencing VHD (has a parent) is not supported; merge it first".into()),
            t => return Err(format!("unknown VHD disk type {}", t)),
        };
        Ok(VhdReader { file, layout, total_size: current_size, position: 0 })
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Virtual size without building the reader (for the size column of the
    /// image list: a dynamic VHD's file size says nothing about the disk).
    pub fn probe_size(path: &str) -> Option<u64> {
        VhdReader::open(path).ok().map(|r| r.total_size)
    }
}

impl Read for VhdReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let want = buf.len().min((self.total_size - self.position) as usize);
        let pos = self.position;
        let n = match &self.layout {
            VhdLayout::Fixed => {
                self.file.seek(SeekFrom::Start(pos))?;
                self.file.read(&mut buf[..want])?
            }
            VhdLayout::Dynamic { blocks, block_size, bitmap_bytes } => {
                let bi = (pos / block_size) as usize;
                let in_block = pos % block_size;
                let n = want.min((block_size - in_block) as usize);
                match blocks.get(bi).copied().flatten() {
                    None => {
                        buf[..n].iter_mut().for_each(|b| *b = 0);
                    }
                    Some(start) => {
                        // honour the sector bitmap: a clear bit is a zero sector
                        let first_sector = in_block / 512;
                        let last_sector = (in_block + n as u64 - 1) / 512;
                        let mut bitmap = vec![0u8; ((last_sector / 8) - (first_sector / 8) + 1) as usize];
                        read_at(&mut self.file, start + first_sector / 8, &mut bitmap)?;
                        read_at(&mut self.file, start + bitmap_bytes + in_block, &mut buf[..n])?;
                        for s in first_sector..=last_sector {
                            let byte = bitmap[(s / 8 - first_sector / 8) as usize];
                            if byte & (0x80 >> (s % 8)) == 0 {
                                let a = (s * 512).saturating_sub(in_block) as usize;
                                let b = (((s + 1) * 512).saturating_sub(in_block) as usize).min(n);
                                if a < b {
                                    buf[a..b].iter_mut().for_each(|x| *x = 0);
                                }
                            }
                        }
                    }
                }
                n
            }
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

fn seek_to(position: &mut u64, total: u64, pos: SeekFrom) -> io::Result<u64> {
    let new_pos = match pos {
        SeekFrom::Start(o) => o as i64,
        SeekFrom::End(o) => total as i64 + o,
        SeekFrom::Current(o) => *position as i64 + o,
    };
    if new_pos < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Seek to a negative position"));
    }
    *position = new_pos as u64;
    Ok(*position)
}

// ───────────────────────────── VHDX ─────────────────────────────

/// GUIDs as stored on disk (first three fields little-endian).
const GUID_BAT: [u8; 16] = [0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08];
const GUID_METADATA: [u8; 16] = [0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E];
const GUID_FILE_PARAMETERS: [u8; 16] = [0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B];
const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8];
const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F];

const VHDX_STATE_MASK: u64 = 0x7;
const VHDX_FULLY_PRESENT: u64 = 6;
const VHDX_PARTIALLY_PRESENT: u64 = 7;

pub struct VhdxReader {
    file: File,
    /// file offset of each payload block's data, or None when it reads as zeros
    blocks: Vec<Option<u64>>,
    block_size: u64,
    total_size: u64,
    position: u64,
}

impl VhdxReader {
    pub fn open(path: &str) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|e| format!("Cannot open VHDX: {}", e))?;
        let mut id = [0u8; 8];
        read_at(&mut file, 0, &mut id).map_err(|e| e.to_string())?;
        if &id != b"vhdxfile" {
            return Err("not a VHDX: no vhdxfile identifier".into());
        }
        // region table: the first valid copy wins (both are identical when clean)
        let mut regions: Option<Vec<([u8; 16], u64, u32)>> = None;
        for off in [192 * 1024u64, 256 * 1024] {
            let mut tbl = vec![0u8; 64 * 1024];
            if read_at(&mut file, off, &mut tbl).is_err() {
                continue;
            }
            if &tbl[..4] != b"regi" {
                continue;
            }
            let count = le32(&tbl, 8) as usize;
            if count > 2047 {
                continue;
            }
            let mut v = Vec::with_capacity(count);
            for i in 0..count {
                let e = 16 + i * 32;
                let mut g = [0u8; 16];
                g.copy_from_slice(&tbl[e..e + 16]);
                v.push((g, le64(&tbl, e + 16), le32(&tbl, e + 24)));
            }
            regions = Some(v);
            break;
        }
        let regions = regions.ok_or("VHDX without a readable region table")?;
        let (bat_off, bat_len) = regions.iter().find(|r| r.0 == GUID_BAT).map(|r| (r.1, r.2)).ok_or("VHDX without a BAT region")?;
        let (meta_off, _) = regions.iter().find(|r| r.0 == GUID_METADATA).map(|r| (r.1, r.2)).ok_or("VHDX without a metadata region")?;

        // metadata table
        let mut mt = vec![0u8; 64 * 1024];
        read_at(&mut file, meta_off, &mut mt).map_err(|e| format!("metadata: {}", e))?;
        if &mt[..8] != b"metadata" {
            return Err("VHDX metadata table signature missing".into());
        }
        let n_items = u16::from_le_bytes([mt[10], mt[11]]) as usize;
        let mut block_size = 0u64;
        let mut has_parent = false;
        let mut virtual_size = 0u64;
        let mut sector_size = 512u64;
        for i in 0..n_items.min(2047) {
            let e = 32 + i * 32;
            let gid = &mt[e..e + 16];
            let off = le32(&mt, e + 16) as u64;
            let len = le32(&mt, e + 20) as usize;
            if len > 1 << 20 {
                continue;
            }
            let mut item = vec![0u8; len];
            if read_at(&mut file, meta_off + off, &mut item).is_err() {
                continue;
            }
            if gid == GUID_FILE_PARAMETERS && len >= 8 {
                block_size = le32(&item, 0) as u64;
                has_parent = le32(&item, 4) & 0x2 != 0;
            } else if gid == GUID_VIRTUAL_DISK_SIZE && len >= 8 {
                virtual_size = le64(&item, 0);
            } else if gid == GUID_LOGICAL_SECTOR_SIZE && len >= 4 {
                sector_size = le32(&item, 0) as u64;
            }
        }
        if has_parent {
            return Err("differencing VHDX (has a parent) is not supported; merge it first".into());
        }
        if block_size == 0 || virtual_size == 0 {
            return Err("VHDX metadata without block size or virtual size".into());
        }
        if !block_size.is_power_of_two() || !(1 << 20..=256 << 20).contains(&block_size)
            || (sector_size != 512 && sector_size != 4096)
            || virtual_size > 64u64 << 40
        {
            return Err(format!(
                "damaged VHDX metadata: block size {}, sector size {}, virtual size {}",
                block_size, sector_size, virtual_size
            ));
        }
        // BAT: payload entries interleaved with one bitmap entry per chunk
        let chunk_ratio = ((1u64 << 23) * sector_size / block_size).max(1);
        let n_blocks = ((virtual_size + block_size - 1) / block_size) as usize;
        let n_entries = n_blocks + n_blocks / chunk_ratio as usize + 1;
        let mut bat = vec![0u8; (n_entries * 8).min(bat_len as usize)];
        read_at(&mut file, bat_off, &mut bat).map_err(|e| format!("BAT: {}", e))?;
        let mut blocks = Vec::with_capacity(n_blocks);
        for i in 0..n_blocks {
            let idx = i + i / chunk_ratio as usize;
            if idx * 8 + 8 > bat.len() {
                blocks.push(None);
                continue;
            }
            let entry = le64(&bat, idx * 8);
            let state = entry & VHDX_STATE_MASK;
            let offset = entry & !0xF_FFFF;
            blocks.push(match state {
                VHDX_FULLY_PRESENT if offset != 0 => Some(offset),
                VHDX_PARTIALLY_PRESENT => return Err("partially present VHDX block: differencing disk".into()),
                _ => None,
            });
        }
        Ok(VhdxReader { file, blocks, block_size, total_size: virtual_size, position: 0 })
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn probe_size(path: &str) -> Option<u64> {
        VhdxReader::open(path).ok().map(|r| r.total_size)
    }
}

impl Read for VhdxReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let want = buf.len().min((self.total_size - self.position) as usize);
        let bi = (self.position / self.block_size) as usize;
        let in_block = self.position % self.block_size;
        let n = want.min((self.block_size - in_block) as usize);
        match self.blocks.get(bi).copied().flatten() {
            None => buf[..n].iter_mut().for_each(|b| *b = 0),
            Some(start) => read_at(&mut self.file, start + in_block, &mut buf[..n])?,
        }
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VhdxReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

/// Open a `.vhd` or `.vhdx` by extension as a boxed `Read + Seek`, with the
/// virtual size, for the image walkers.
pub fn open_virtual_disk(path: &str) -> Result<(Box<dyn ReadSeek>, u64), String> {
    let ext = Path::new(path).extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).unwrap_or_default();
    if ext == "vhdx" {
        let r = VhdxReader::open(path)?;
        let n = r.total_size();
        Ok((Box::new(r), n))
    } else {
        let r = VhdReader::open(path)?;
        let n = r.total_size();
        Ok((Box::new(r), n))
    }
}

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("masstin-vhd-test-{}-{}", std::process::id(), name));
        p.to_string_lossy().to_string()
    }

    fn vhd_footer(size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[..8].copy_from_slice(b"conectix");
        f[16..24].copy_from_slice(&data_offset.to_be_bytes());
        f[40..48].copy_from_slice(&size.to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&disk_type.to_be_bytes());
        f
    }

    #[test]
    fn fixed_vhd_is_raw_plus_footer() {
        let p = tmp("fixed.vhd");
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut f = File::create(&p).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&vhd_footer(4096, VHD_FIXED, u64::MAX)).unwrap();
        drop(f);
        let mut r = VhdReader::open(&p).unwrap();
        assert_eq!(r.total_size(), 4096);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut b = [0u8; 8];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b[..], &data[1000..1008]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn dynamic_vhd_reads_allocated_blocks_and_zero_holes() {
        // virtual disk of 3 blocks of 4 KB: block 0 allocated (sectors 0..7
        // present except sector 3), block 1 unallocated, block 2 allocated
        let p = tmp("dyn.vhd");
        let block = 4096u64;
        let size = 3 * block;
        let mut img: Vec<u8> = Vec::new();
        img.extend_from_slice(&vhd_footer(size, VHD_DYNAMIC, 512)); // copy of the footer
        let mut hdr = vec![0u8; 1024];
        hdr[..8].copy_from_slice(b"cxsparse");
        hdr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        hdr[16..24].copy_from_slice(&1536u64.to_be_bytes()); // BAT at 1536
        hdr[28..32].copy_from_slice(&3u32.to_be_bytes());
        hdr[32..36].copy_from_slice(&(block as u32).to_be_bytes());
        img.extend_from_slice(&hdr);
        // BAT (3 entries, padded to a sector)
        let b0 = 2048u64 / 512; // block 0 at 2048
        let b2 = (2048 + 512 + block) / 512; // block 2 right after block 0 (bitmap + data)
        let mut bat = vec![0u8; 512];
        bat[0..4].copy_from_slice(&(b0 as u32).to_be_bytes());
        bat[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        bat[8..12].copy_from_slice(&(b2 as u32).to_be_bytes());
        img.extend_from_slice(&bat);
        // block 0: bitmap (sector 3 clear) + data
        let mut bm = vec![0u8; 512];
        bm[0] = 0b1110_1111;
        img.extend_from_slice(&bm);
        let d0: Vec<u8> = (0..block as usize).map(|i| (i % 7 + 1) as u8).collect();
        img.extend_from_slice(&d0);
        // block 2: all sectors present
        let mut bm2 = vec![0u8; 512];
        bm2[0] = 0xFF;
        img.extend_from_slice(&bm2);
        let d2: Vec<u8> = (0..block as usize).map(|i| (i % 5 + 10) as u8).collect();
        img.extend_from_slice(&d2);
        img.extend_from_slice(&vhd_footer(size, VHD_DYNAMIC, 512));
        std::fs::write(&p, &img).unwrap();

        let mut r = VhdReader::open(&p).unwrap();
        assert_eq!(r.total_size(), size);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out.len() as u64, size);
        assert_eq!(&out[..1536], &d0[..1536]);
        assert!(out[1536..2048].iter().all(|b| *b == 0), "sector 3 of block 0 is a zero sector");
        assert_eq!(&out[2048..4096], &d0[2048..]);
        assert!(out[4096..8192].iter().all(|b| *b == 0), "unallocated block reads as zeros");
        assert_eq!(&out[8192..], &d2[..]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn differencing_vhd_is_refused() {
        let p = tmp("diff.vhd");
        std::fs::write(&p, vhd_footer(4096, VHD_DIFFERENCING, 512)).unwrap();
        assert!(VhdReader::open(&p).err().expect("refused").contains("differencing"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn vhdx_bat_index_skips_bitmap_entries() {
        // chunk ratio 4: payload blocks 0..3 at entries 0..3, entry 4 is a
        // bitmap, block 4 at entry 5
        let chunk_ratio = 4usize;
        let idx = |i: usize| i + i / chunk_ratio;
        assert_eq!((0..6).map(idx).collect::<Vec<_>>(), vec![0, 1, 2, 3, 5, 6]);
    }
}
