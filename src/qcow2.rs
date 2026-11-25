//! Reader for QEMU's QCOW2 virtual disks (versions 2 and 3), the format of
//! KVM / libvirt, Proxmox, OpenStack and Nutanix AHV. It exposes the virtual
//! disk as `Read + Seek`, the same surface as `VhdReader` and `VmdkReader`,
//! so the NTFS / ext4 walkers and the carver use it unchanged.
//!
//! The file starts with a big-endian header ("QFI\xfb"): the cluster size
//! (512 bytes to 2 MiB, 64 KiB by default), the size of the virtual disk and
//! the place of the L1 table. A guest offset is looked up in two steps: the
//! L1 entry names an L2 table (one cluster of entries), the L2 entry names
//! the cluster in the file that holds the data. A cluster is then one of:
//!
//! * allocated: its bytes are in the file at the offset the entry gives;
//! * compressed: the entry gives a byte offset and a length in sectors, and
//!   the bytes are raw deflate or, when the header says so, a zstd frame;
//! * zero: reads as zeros whatever lies under it;
//! * unallocated: reads from the backing file when the image has one (an
//!   overlay, as a snapshot leaves), else as zeros.
//!
//! With extended L2 entries (16 bytes, QEMU 5.2) each cluster is cut in 32
//! subclusters and a bitmap says for each one which of the above it is.
//!
//! A backing file is looked for where the header names it, then next to the
//! image under the same relative path, then next to the image under its bare
//! name (evidence copied off a hypervisor keeps the hypervisor's path). It
//! may be another QCOW2 or a raw disk; the chain is followed to its end.
//!
//! Refused with an error that says why: encrypted images (AES or LUKS),
//! images whose data lives in an external data file, QCOW version 1, an
//! overlay whose backing file is not there, and incompatible features this
//! reader does not know. Internal snapshots are not read: the disk is the
//! active state. The image is read as a file and never written; the dirty
//! bit of an image that was not closed cleanly concerns the reference counts
//! only, which a reader does not use.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::vhd::ReadSeek;

/// The four bytes every QCOW image starts with.
pub const QCOW_MAGIC: &[u8; 4] = b"QFI\xfb";

/// L2 tables kept in memory: with 64 KiB clusters each one maps 512 MiB.
const L2_CACHE_TABLES: usize = 64;
/// QEMU's own limit for the L1 table: 32 MiB of entries.
const MAX_L1_ENTRIES: u64 = 32 * 1024 * 1024 / 8;
/// A chain of overlays longer than this is a loop.
const MAX_BACKING_DEPTH: usize = 64;

const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const FLAG_COMPRESSED: u64 = 1 << 62;
const FLAG_ZERO: u64 = 1;

const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPAT_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;
/// dirty (0) and corrupt (1) do not change how the image is read
const INCOMPAT_KNOWN: u64 = 0b1_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    Deflate,
    Zstd,
}

/// What the header says, before any table is read.
#[derive(Debug, Clone)]
struct Header {
    cluster_bits: u32,
    size: u64,
    l1_size: u64,
    l1_offset: u64,
    extended_l2: bool,
    compression: Compression,
    backing: Option<String>,
    /// the format of the backing file as the image declares it ("raw", "qcow2"...)
    backing_format: Option<String>,
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]])
}

/// Reads as much of `buf` as the file has from `offset`; the rest stays as it was.
fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    file.seek(SeekFrom::Start(offset))?;
    let mut done = 0;
    while done < buf.len() {
        match file.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

fn parse_header(file: &mut File, file_len: u64) -> Result<Header, String> {
    let mut h = [0u8; 112];
    let got = read_at(file, 0, &mut h).map_err(|e| format!("cannot read the QCOW2 header: {e}"))?;
    if got < 72 || &h[..4] != QCOW_MAGIC {
        return Err("not a QCOW2 image (no QFI header)".to_string());
    }
    let version = be32(&h, 4);
    if version == 1 {
        return Err("QCOW version 1 image: only QCOW2 (versions 2 and 3) is read; convert it with `qemu-img convert -O qcow2`".to_string());
    }
    if version != 2 && version != 3 {
        return Err(format!("QCOW2 version {version} is not known (2 and 3 are read)"));
    }
    let backing_offset = be64(&h, 8);
    let backing_len = be32(&h, 16) as u64;
    let cluster_bits = be32(&h, 20);
    let size = be64(&h, 24);
    let crypt = be32(&h, 32);
    let l1_size = be32(&h, 36) as u64;
    let l1_offset = be64(&h, 40);
    if !(9..=21).contains(&cluster_bits) {
        return Err(format!("QCOW2 header: cluster size of 2^{cluster_bits} bytes is out of range"));
    }
    match crypt {
        0 => {}
        1 => return Err("QCOW2 image encrypted with AES: it cannot be read without its key; decrypt it with qemu-img first".to_string()),
        2 => return Err("QCOW2 image encrypted with LUKS: it cannot be read without its key; decrypt it with qemu-img first".to_string()),
        n => return Err(format!("QCOW2 image encrypted with an unknown method ({n})")),
    }
    let (mut incompat, mut header_len) = (0u64, 72u64);
    if version == 3 {
        if got < 104 {
            return Err("QCOW2 header: truncated".to_string());
        }
        incompat = be64(&h, 72);
        header_len = be32(&h, 100) as u64;
        if header_len < 104 {
            return Err(format!("QCOW2 header: length of {header_len} bytes is too short for version 3"));
        }
    }
    if incompat & !INCOMPAT_KNOWN != 0 {
        return Err(format!("QCOW2 image uses features this reader does not know (incompatible feature bits {:#x})", incompat & !INCOMPAT_KNOWN));
    }
    if incompat & INCOMPAT_EXTERNAL_DATA != 0 {
        return Err("QCOW2 image whose data is in an external data file: only the metadata is in this file; convert the pair with `qemu-img convert -O raw`".to_string());
    }
    let compression = if incompat & INCOMPAT_COMPRESSION_TYPE != 0 && header_len > 104 {
        match h[104] {
            0 => Compression::Deflate,
            1 => Compression::Zstd,
            n => return Err(format!("QCOW2 image compressed with an unknown method ({n})")),
        }
    } else {
        Compression::Deflate
    };
    let extended_l2 = incompat & INCOMPAT_EXTENDED_L2 != 0;
    let cluster_size = 1u64 << cluster_bits;
    if extended_l2 && cluster_bits < 14 {
        return Err("QCOW2 header: extended L2 entries with clusters under 16 KiB".to_string());
    }
    let l2_entries = cluster_size / if extended_l2 { 16 } else { 8 };
    let needed = size.div_ceil(cluster_size).div_ceil(l2_entries);
    if l1_size > MAX_L1_ENTRIES || l1_size < needed {
        return Err(format!("QCOW2 header: an L1 table of {l1_size} entries for a disk that needs {needed}"));
    }
    if l1_size > 0 && (l1_offset == 0 || l1_offset % cluster_size != 0 || l1_offset.saturating_add(l1_size * 8) > file_len) {
        return Err("QCOW2 header: the L1 table lies outside the file (a truncated image?)".to_string());
    }

    // the rest of the first cluster: the header extensions and the backing file's name
    let mut first = vec![0u8; cluster_size.min(file_len) as usize];
    read_at(file, 0, &mut first).map_err(|e| format!("cannot read the QCOW2 header: {e}"))?;
    let mut backing_format = None;
    let mut at = header_len as usize;
    let end = if backing_offset != 0 { (backing_offset as usize).min(first.len()) } else { first.len() };
    while at + 8 <= end {
        let (kind, len) = (be32(&first, at), be32(&first, at + 4) as usize);
        at += 8;
        if kind == 0 || at + len > end {
            break;
        }
        if kind == 0xE279_2ACA {
            backing_format = Some(String::from_utf8_lossy(&first[at..at + len]).trim_end_matches('\0').to_ascii_lowercase());
        }
        at += len.div_ceil(8) * 8;
    }
    let backing = if backing_offset != 0 && backing_len != 0 {
        let (a, b) = (backing_offset as usize, (backing_offset + backing_len) as usize);
        if backing_len > 1023 || b > first.len() {
            return Err("QCOW2 header: the backing file's name lies outside the first cluster".to_string());
        }
        Some(String::from_utf8_lossy(&first[a..b]).to_string())
    } else {
        None
    };
    Ok(Header { cluster_bits, size, l1_size, l1_offset, extended_l2, compression, backing, backing_format })
}

/// Where the backing file an image names is: as named, then relative to the
/// image's folder, then by its bare name in the image's folder.
fn find_backing(image: &Path, name: &str) -> Option<PathBuf> {
    let dir = image.parent().unwrap_or_else(|| Path::new("."));
    let bare = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // a relative name is relative to the image, never to where masstin runs
    let mut tries = Vec::new();
    if Path::new(name).is_absolute() {
        tries.push(PathBuf::from(name));
    }
    tries.push(dir.join(name));
    if !bare.is_empty() {
        tries.push(dir.join(bare));
    }
    tries.into_iter().find(|p| p.is_file())
}

/// A QCOW2 virtual disk, with its chain of backing files, as one disk.
pub struct Qcow2Reader {
    file: File,
    file_len: u64,
    cluster_bits: u32,
    cluster_size: u64,
    size: u64,
    l1: Vec<u64>,
    extended_l2: bool,
    l2_entries: u64,
    compression: Compression,
    backing: Option<(Box<dyn ReadSeek>, u64)>,
    l2_cache: HashMap<u64, Vec<u8>>,
    l2_order: VecDeque<u64>,
    /// the last compressed cluster read, by its guest cluster number
    inflated: Option<(u64, Vec<u8>)>,
    pos: u64,
}

impl Qcow2Reader {
    pub fn open(path: &str) -> Result<Self, String> {
        Self::open_at_depth(path, 0)
    }

    fn open_at_depth(path: &str, depth: usize) -> Result<Self, String> {
        if depth > MAX_BACKING_DEPTH {
            return Err("QCOW2 backing chain: more than 64 files deep (a loop?)".to_string());
        }
        let mut file = File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
        let file_len = file.metadata().map_err(|e| format!("cannot stat {path}: {e}"))?.len();
        let h = parse_header(&mut file, file_len)?;

        let mut raw = vec![0u8; (h.l1_size * 8) as usize];
        let got = read_at(&mut file, h.l1_offset, &mut raw).map_err(|e| format!("cannot read the QCOW2 L1 table: {e}"))?;
        if got < raw.len() {
            return Err("QCOW2 image: the L1 table is cut short (a truncated image?)".to_string());
        }
        let l1 = raw.chunks_exact(8).map(|c| be64(c, 0)).collect();

        let backing = match &h.backing {
            None => None,
            Some(name) => {
                if name.starts_with("json:") || name.contains("://") {
                    return Err(format!("QCOW2 overlay: its backing file is not a local file ({name}); flatten it with `qemu-img convert -O raw`"));
                }
                let found = find_backing(Path::new(path), name).ok_or_else(|| {
                    format!("QCOW2 overlay: it holds only the changes over '{name}', which is not there; put that backing file in the same folder as the image")
                })?;
                Some(open_backing(&found, h.backing_format.as_deref(), depth + 1)?)
            }
        };

        let cluster_size = 1u64 << h.cluster_bits;
        Ok(Qcow2Reader {
            file,
            file_len,
            cluster_bits: h.cluster_bits,
            cluster_size,
            size: h.size,
            l1,
            extended_l2: h.extended_l2,
            l2_entries: cluster_size / if h.extended_l2 { 16 } else { 8 },
            compression: h.compression,
            backing,
            l2_cache: HashMap::new(),
            l2_order: VecDeque::new(),
            inflated: None,
            pos: 0,
        })
    }

    /// The size of the virtual disk.
    pub fn total_size(&self) -> u64 {
        self.size
    }

    /// The size of the virtual disk, from the header alone.
    pub fn probe_size(path: &str) -> Option<u64> {
        let mut file = File::open(path).ok()?;
        let len = file.metadata().ok()?.len();
        parse_header(&mut file, len).ok().map(|h| h.size)
    }

    fn bad(what: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, what.into())
    }

    /// The L2 entry of a guest cluster and, with extended entries, its
    /// subcluster bitmap. `None` when no L2 table covers the cluster.
    fn l2_entry(&mut self, cluster: u64) -> io::Result<Option<(u64, u64)>> {
        let l1_index = (cluster / self.l2_entries) as usize;
        let table = match self.l1.get(l1_index) {
            Some(e) if e & OFFSET_MASK != 0 => e & OFFSET_MASK,
            _ => return Ok(None),
        };
        if !self.l2_cache.contains_key(&table) {
            let mut buf = vec![0u8; self.cluster_size as usize];
            let got = read_at(&mut self.file, table, &mut buf)?;
            if got < buf.len() {
                return Err(Self::bad(format!("QCOW2: the L2 table at {table:#x} is cut short")));
            }
            if self.l2_order.len() >= L2_CACHE_TABLES {
                if let Some(old) = self.l2_order.pop_front() {
                    self.l2_cache.remove(&old);
                }
            }
            self.l2_order.push_back(table);
            self.l2_cache.insert(table, buf);
        }
        let buf = &self.l2_cache[&table];
        let width = if self.extended_l2 { 16 } else { 8 };
        let at = (cluster % self.l2_entries) as usize * width;
        let bitmap = if self.extended_l2 { be64(buf, at + 8) } else { 0 };
        Ok(Some((be64(buf, at), bitmap)))
    }

    /// The bytes of a compressed cluster, inflated to a whole cluster.
    fn inflate(&mut self, cluster: u64, entry: u64) -> io::Result<()> {
        if matches!(&self.inflated, Some((c, _)) if *c == cluster) {
            return Ok(());
        }
        let sector_bits = self.cluster_bits - 8;
        let x = 62 - sector_bits;
        let host = entry & ((1u64 << x) - 1);
        let sectors = (entry >> x) & ((1u64 << sector_bits) - 1);
        let span = (sectors + 1) * 512 - (host & 511);
        if host >= self.file_len {
            return Err(Self::bad(format!("QCOW2: a compressed cluster at {host:#x}, past the end of the file")));
        }
        let mut packed = vec![0u8; span.min(self.file_len - host) as usize];
        let got = read_at(&mut self.file, host, &mut packed)?;
        packed.truncate(got);
        let mut out = Vec::with_capacity(self.cluster_size as usize);
        // the stream ends before the sectors do: what follows it is another cluster's
        let read = match self.compression {
            Compression::Deflate => flate2::read::DeflateDecoder::new(&packed[..]).take(self.cluster_size).read_to_end(&mut out),
            Compression::Zstd => zstd::stream::read::Decoder::new(&packed[..]).map(|d| d.single_frame()).and_then(|d| d.take(self.cluster_size).read_to_end(&mut out)),
        };
        if let Err(e) = read {
            // deflate cut at the end of its sectors after the last byte it owes
            if out.len() < self.cluster_size as usize {
                return Err(Self::bad(format!("QCOW2: the compressed cluster at {host:#x} does not inflate: {e}")));
            }
        }
        if out.len() < self.cluster_size as usize {
            return Err(Self::bad(format!("QCOW2: the compressed cluster at {host:#x} inflates to {} bytes, not a whole cluster", out.len())));
        }
        self.inflated = Some((cluster, out));
        Ok(())
    }

    /// What lies under this image at `pos`: the backing file, or zeros.
    fn read_under(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        buf.fill(0);
        if let Some((disk, len)) = &mut self.backing {
            if pos < *len {
                let n = ((*len - pos) as usize).min(buf.len());
                disk.seek(SeekFrom::Start(pos))?;
                let mut done = 0;
                while done < n {
                    match disk.read(&mut buf[done..n]) {
                        Ok(0) => break,
                        Ok(k) => done += k,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Ok(())
    }
}

/// Opens a backing file: another QCOW2 by its header, else a raw disk.
fn open_backing(path: &Path, declared: Option<&str>, depth: usize) -> Result<(Box<dyn ReadSeek>, u64), String> {
    let shown = path.to_string_lossy().to_string();
    let mut magic = [0u8; 4];
    let is_qcow = File::open(path).and_then(|mut f| f.read_exact(&mut magic)).map(|_| &magic == QCOW_MAGIC).unwrap_or(false);
    if is_qcow {
        let r = Qcow2Reader::open_at_depth(&shown, depth)?;
        let n = r.total_size();
        return Ok((Box::new(r), n));
    }
    match declared {
        None | Some("raw") | Some("file") | Some("host_device") => {
            let f = File::open(path).map_err(|e| format!("cannot open the backing file {shown}: {e}"))?;
            let n = f.metadata().map_err(|e| format!("cannot stat the backing file {shown}: {e}"))?.len();
            Ok((Box::new(f), n))
        }
        Some(other) => Err(format!("QCOW2 overlay: its backing file {shown} is in the {other} format, which is not followed; flatten the chain with `qemu-img convert -O raw`")),
    }
}

impl Read for Qcow2Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let cluster = self.pos >> self.cluster_bits;
        let within = self.pos & (self.cluster_size - 1);
        // one piece: to the end of the cluster, or of the subcluster
        let piece = if self.extended_l2 { self.cluster_size / 32 } else { self.cluster_size };
        let room = piece - (within % piece);
        let n = (buf.len() as u64).min(room).min(self.size - self.pos) as usize;
        let out = &mut buf[..n];
        let pos = self.pos;

        match self.l2_entry(cluster)? {
            None => self.read_under(pos, out)?,
            Some((entry, _)) if entry & FLAG_COMPRESSED != 0 => {
                self.inflate(cluster, entry)?;
                let data = &self.inflated.as_ref().expect("just inflated").1;
                out.copy_from_slice(&data[within as usize..within as usize + n]);
            }
            Some((entry, bitmap)) => {
                let host = entry & OFFSET_MASK;
                let (zero, allocated) = if self.extended_l2 {
                    let sub = within / piece;
                    ((bitmap >> (32 + sub)) & 1 == 1, (bitmap >> sub) & 1 == 1 && host != 0)
                } else {
                    (entry & FLAG_ZERO != 0, host != 0)
                };
                if zero {
                    out.fill(0);
                } else if allocated {
                    out.fill(0);
                    // a cluster past the end of a truncated file reads as zeros
                    read_at(&mut self.file, host + within, out)?;
                } else {
                    self.read_under(pos, out)?;
                }
            }
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Qcow2Reader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.size as i128 + n as i128,
            SeekFrom::Current(n) => self.pos as i128 + n as i128,
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before the start of the disk"));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("masstin-qcow2-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// What a cluster of the image under construction is.
    #[derive(Clone)]
    enum Cl {
        Hole,
        Zero,
        Data(Vec<u8>),
        Packed(Vec<u8>),
        /// extended L2: data, and the allocation and zero bits of its 32 subclusters
        Sub(Vec<u8>, u32, u32),
    }

    struct Build {
        bits: u32,
        version: u32,
        zstd: bool,
        extended: bool,
        crypt: u32,
        incompat_extra: u64,
        backing: Option<(String, Option<&'static str>)>,
        size: Option<u64>,
        clusters: Vec<Cl>,
    }

    impl Build {
        fn new(bits: u32, clusters: Vec<Cl>) -> Self {
            Build { bits, version: 3, zstd: false, extended: false, crypt: 0, incompat_extra: 0, backing: None, size: None, clusters }
        }

        /// header + extensions + backing name in cluster 0, the L1 table in
        /// cluster 1, one L2 table in cluster 2, then the data.
        fn write(&self, path: &Path) {
            let cs = 1usize << self.bits;
            let width = if self.extended { 16 } else { 8 };
            assert!(self.clusters.len() <= cs / width, "one L2 table only");
            let mut img = vec![0u8; cs * 3];
            let size = self.size.unwrap_or((self.clusters.len() * cs) as u64);
            img[..4].copy_from_slice(QCOW_MAGIC);
            img[4..8].copy_from_slice(&self.version.to_be_bytes());
            img[20..24].copy_from_slice(&self.bits.to_be_bytes());
            img[24..32].copy_from_slice(&size.to_be_bytes());
            img[32..36].copy_from_slice(&self.crypt.to_be_bytes());
            img[36..40].copy_from_slice(&1u32.to_be_bytes());
            img[40..48].copy_from_slice(&(cs as u64).to_be_bytes());
            let mut at = 72;
            if self.version == 3 {
                let mut incompat = self.incompat_extra;
                if self.zstd {
                    incompat |= INCOMPAT_COMPRESSION_TYPE;
                }
                if self.extended {
                    incompat |= INCOMPAT_EXTENDED_L2;
                }
                img[72..80].copy_from_slice(&incompat.to_be_bytes());
                img[96..100].copy_from_slice(&4u32.to_be_bytes());
                img[100..104].copy_from_slice(&112u32.to_be_bytes());
                img[104] = self.zstd as u8;
                at = 112;
            }
            if let Some((name, format)) = &self.backing {
                if let Some(f) = format {
                    img[at..at + 4].copy_from_slice(&0xE279_2ACAu32.to_be_bytes());
                    img[at + 4..at + 8].copy_from_slice(&(f.len() as u32).to_be_bytes());
                    img[at + 8..at + 8 + f.len()].copy_from_slice(f.as_bytes());
                    at += 8 + f.len().div_ceil(8) * 8;
                }
                at += 8; // the end-of-extensions marker
                img[8..16].copy_from_slice(&(at as u64).to_be_bytes());
                img[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
                img[at..at + name.len()].copy_from_slice(name.as_bytes());
            }
            // L1: one entry, the L2 table in cluster 2
            img[cs..cs + 8].copy_from_slice(&((2 * cs) as u64 | 1 << 63).to_be_bytes());
            for (i, c) in self.clusters.iter().enumerate() {
                let (mut entry, mut bitmap) = (0u64, 0u64);
                match c {
                    Cl::Hole => {}
                    Cl::Zero => {
                        if self.extended {
                            bitmap = 0xffff_ffff << 32;
                        } else {
                            entry = FLAG_ZERO;
                        }
                    }
                    Cl::Data(d) => {
                        assert_eq!(d.len(), cs);
                        entry = img.len() as u64 | 1 << 63;
                        bitmap = 0xffff_ffff;
                        img.extend_from_slice(d);
                    }
                    Cl::Sub(d, alloc, zero) => {
                        assert_eq!(d.len(), cs);
                        entry = img.len() as u64 | 1 << 63;
                        bitmap = *alloc as u64 | (*zero as u64) << 32;
                        img.extend_from_slice(d);
                    }
                    Cl::Packed(d) => {
                        assert_eq!(d.len(), cs);
                        let packed = if self.zstd {
                            zstd::stream::encode_all(&d[..], 3).unwrap()
                        } else {
                            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                            e.write_all(d).unwrap();
                            e.finish().unwrap()
                        };
                        // not sector-aligned, as QEMU packs them one after another
                        img.extend_from_slice(&[0xAA; 37]);
                        let host = img.len() as u64;
                        img.extend_from_slice(&packed);
                        let x = 62 - (self.bits - 8);
                        let sectors = (host % 512 + packed.len() as u64).div_ceil(512) - 1;
                        entry = FLAG_COMPRESSED | sectors << x | host;
                        // what follows the stream inside its last sector is not its own
                        img.extend_from_slice(&[0x55; 700]);
                        let pad = img.len().div_ceil(cs) * cs;
                        img.resize(pad, 0);
                    }
                }
                let o = 2 * cs + i * width;
                img[o..o + 8].copy_from_slice(&entry.to_be_bytes());
                if self.extended {
                    img[o + 8..o + 16].copy_from_slice(&bitmap.to_be_bytes());
                }
            }
            std::fs::write(path, img).unwrap();
        }
    }

    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(31).wrapping_add(seed as u32 * 7) as u8 ^ (i >> 8) as u8).collect()
    }

    /// Repetitive, so that it compresses, and still different at every offset.
    fn text(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| b"lateral movement "[(i + seed as usize) % 17] ^ ((i / 4096) as u8)).collect()
    }

    fn all(path: &Path) -> Vec<u8> {
        let mut r = Qcow2Reader::open(path.to_str().unwrap()).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out.len() as u64, r.total_size());
        out
    }

    #[test]
    fn data_zero_and_hole_clusters() {
        let cs = 1 << 16;
        let (a, b) = (pattern(1, cs), pattern(2, cs));
        let p = tmp("plain.qcow2");
        Build::new(16, vec![Cl::Data(a.clone()), Cl::Hole, Cl::Zero, Cl::Data(b.clone())]).write(&p);
        let got = all(&p);
        assert_eq!(&got[..cs], &a[..]);
        assert!(got[cs..3 * cs].iter().all(|&x| x == 0));
        assert_eq!(&got[3 * cs..], &b[..]);
        assert_eq!(Qcow2Reader::probe_size(p.to_str().unwrap()), Some(4 * cs as u64));
    }

    #[test]
    fn version_2_and_small_clusters() {
        for bits in [9u32, 12, 21] {
            let cs = 1usize << bits;
            let a = pattern(bits as u8, cs);
            let p = tmp(&format!("v2-{bits}.qcow2"));
            let mut b = Build::new(bits, vec![Cl::Hole, Cl::Data(a.clone()), Cl::Packed(text(3, cs))]);
            b.version = 2;
            b.write(&p);
            let got = all(&p);
            assert!(got[..cs].iter().all(|&x| x == 0));
            assert_eq!(&got[cs..2 * cs], &a[..]);
            assert_eq!(&got[2 * cs..], &text(3, cs)[..]);
        }
    }

    #[test]
    fn compressed_clusters_deflate_and_zstd() {
        let cs = 1 << 16;
        for zstd in [false, true] {
            let p = tmp(if zstd { "zstd.qcow2" } else { "deflate.qcow2" });
            let mut b = Build::new(16, vec![Cl::Packed(text(1, cs)), Cl::Data(pattern(9, cs)), Cl::Packed(text(2, cs)), Cl::Packed(vec![0u8; cs])]);
            b.zstd = zstd;
            b.write(&p);
            let got = all(&p);
            assert_eq!(&got[..cs], &text(1, cs)[..]);
            assert_eq!(&got[cs..2 * cs], &pattern(9, cs)[..]);
            assert_eq!(&got[2 * cs..3 * cs], &text(2, cs)[..]);
            assert!(got[3 * cs..].iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn seeks_and_reads_across_clusters() {
        let cs = 1usize << 12;
        let parts: Vec<Vec<u8>> = (0..6).map(|i| pattern(i, cs)).collect();
        let p = tmp("seek.qcow2");
        let mut b = Build::new(12, vec![Cl::Data(parts[0].clone()), Cl::Packed(text(7, cs)), Cl::Data(parts[2].clone()), Cl::Hole, Cl::Data(parts[4].clone())]);
        b.size = Some(5 * cs as u64 - 100); // a disk that ends inside its last cluster
        b.write(&p);
        let whole = all(&p);
        assert_eq!(whole.len(), 5 * cs - 100);
        let mut r = Qcow2Reader::open(p.to_str().unwrap()).unwrap();
        for (from, len) in [(0usize, 10usize), (cs - 3, 9), (cs + 100, 3 * cs), (2 * cs - 1, 2), (5 * cs - 200, 500), (4 * cs, 1)] {
            r.seek(SeekFrom::Start(from as u64)).unwrap();
            let mut buf = vec![0xEEu8; len];
            let mut done = 0;
            while done < len {
                let n = r.read(&mut buf[done..]).unwrap();
                if n == 0 {
                    break;
                }
                done += n;
            }
            assert_eq!(&buf[..done], &whole[from..(from + len).min(whole.len())], "from {from} len {len}");
        }
        assert_eq!(r.seek(SeekFrom::End(-1)).unwrap(), 5 * cs as u64 - 101);
        assert_eq!(r.seek(SeekFrom::Current(1)).unwrap(), 5 * cs as u64 - 100);
        assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 0);
        assert!(r.seek(SeekFrom::Current(-(1 << 40))).is_err());
    }

    #[test]
    fn overlay_over_a_raw_backing_file() {
        let cs = 1usize << 12;
        let base: Vec<u8> = pattern(40, 3 * cs + 100); // shorter than the overlay
        std::fs::write(tmp("base-raw.img"), &base).unwrap();
        let changed = pattern(41, cs);
        let p = tmp("over-raw.qcow2");
        let mut b = Build::new(12, vec![Cl::Hole, Cl::Data(changed.clone()), Cl::Zero, Cl::Hole, Cl::Hole]);
        b.backing = Some(("base-raw.img".to_string(), Some("raw")));
        b.write(&p);
        let got = all(&p);
        assert_eq!(&got[..cs], &base[..cs]);
        assert_eq!(&got[cs..2 * cs], &changed[..]);
        assert!(got[2 * cs..3 * cs].iter().all(|&x| x == 0), "a zero cluster hides the backing file");
        assert_eq!(&got[3 * cs..3 * cs + 100], &base[3 * cs..]);
        assert!(got[3 * cs + 100..].iter().all(|&x| x == 0), "past the end of the backing file");
    }

    #[test]
    fn chain_of_three_and_a_hypervisor_path() {
        let cs = 1usize << 12;
        let (a, b1, c) = (pattern(50, cs), pattern(51, cs), pattern(52, cs));
        Build::new(12, vec![Cl::Data(a.clone()), Cl::Data(a.clone()), Cl::Data(a.clone())]).write(&tmp("chain-0.qcow2"));
        let mut mid = Build::new(12, vec![Cl::Hole, Cl::Data(b1.clone()), Cl::Hole]);
        // as the hypervisor wrote it: a path that does not exist here
        mid.backing = Some(("/var/lib/libvirt/images/chain-0.qcow2".to_string(), Some("qcow2")));
        mid.write(&tmp("chain-1.qcow2"));
        let mut top = Build::new(12, vec![Cl::Hole, Cl::Hole, Cl::Data(c.clone())]);
        top.backing = Some(("chain-1.qcow2".to_string(), None));
        top.write(&tmp("chain-2.qcow2"));
        let got = all(&tmp("chain-2.qcow2"));
        assert_eq!(&got[..cs], &a[..]);
        assert_eq!(&got[cs..2 * cs], &b1[..]);
        assert_eq!(&got[2 * cs..], &c[..]);
    }

    #[test]
    fn extended_l2_subclusters() {
        let cs = 1usize << 16;
        let sub = cs / 32;
        let base = pattern(60, 2 * cs);
        std::fs::write(tmp("base-sub.img"), &base).unwrap();
        let data = pattern(61, cs);
        let p = tmp("sub.qcow2");
        // subclusters 0 and 5 allocated, 7 zero, the rest from the backing file
        let mut b = Build::new(16, vec![Cl::Sub(data.clone(), 0b10_0001, 0b1000_0000), Cl::Zero, Cl::Packed(text(4, cs)), Cl::Data(pattern(62, cs))]);
        b.extended = true;
        b.backing = Some(("base-sub.img".to_string(), Some("raw")));
        b.write(&p);
        let got = all(&p);
        for s in 0..32 {
            let (from, to) = (s * sub, (s + 1) * sub);
            match s {
                0 | 5 => assert_eq!(&got[from..to], &data[from..to], "subcluster {s}"),
                7 => assert!(got[from..to].iter().all(|&x| x == 0), "subcluster {s}"),
                _ => assert_eq!(&got[from..to], &base[from..to], "subcluster {s}"),
            }
        }
        assert!(got[cs..2 * cs].iter().all(|&x| x == 0));
        assert_eq!(&got[2 * cs..3 * cs], &text(4, cs)[..]);
        assert_eq!(&got[3 * cs..], &pattern(62, cs)[..]);
    }

    #[test]
    fn refusals_say_why() {
        let cs = 1usize << 12;
        let open = |b: &Build, name: &str| {
            let p = tmp(name);
            b.write(&p);
            Qcow2Reader::open(p.to_str().unwrap()).err().unwrap_or_default()
        };
        let one = || vec![Cl::Data(pattern(1, cs))];
        let mut b = Build::new(12, one());
        b.crypt = 2;
        assert!(open(&b, "luks.qcow2").contains("LUKS"));
        b.crypt = 1;
        assert!(open(&b, "aes.qcow2").contains("AES"));
        let mut b = Build::new(12, one());
        b.incompat_extra = INCOMPAT_EXTERNAL_DATA;
        assert!(open(&b, "external.qcow2").contains("external data file"));
        let mut b = Build::new(12, one());
        b.incompat_extra = 1 << 9;
        assert!(open(&b, "future.qcow2").contains("does not know"));
        let mut b = Build::new(12, one());
        b.version = 1;
        assert!(open(&b, "v1.qcow").contains("version 1"));
        let mut b = Build::new(12, one());
        b.backing = Some(("not-there.qcow2".to_string(), None));
        let e = open(&b, "orphan.qcow2");
        assert!(e.contains("not-there.qcow2") && e.contains("same folder"), "{e}");
        let mut b = Build::new(12, one());
        b.backing = Some(("nbd://10.0.0.1/disk".to_string(), None));
        assert!(open(&b, "remote.qcow2").contains("not a local file"));
        // dirty and corrupt bits: read all the same
        let mut b = Build::new(12, one());
        b.incompat_extra = 0b11;
        assert_eq!(open(&b, "dirty.qcow2"), "");
        // a file that only starts like one
        let p = tmp("short.qcow2");
        std::fs::write(&p, b"QFI\xfb\0\0\0\x03").unwrap();
        assert!(Qcow2Reader::open(p.to_str().unwrap()).is_err());
        let p = tmp("other.qcow2");
        std::fs::write(&p, vec![0u8; 4096]).unwrap();
        assert!(Qcow2Reader::open(p.to_str().unwrap()).err().unwrap().contains("not a QCOW2"));
    }

    /// A backing file named without a folder is looked for next to the
    /// image, not in the folder masstin runs from.
    #[test]
    fn backing_file_is_relative_to_the_image() {
        let here = std::env::current_dir().unwrap();
        let name = format!("masstin-qcow2-cwd-{}.img", std::process::id());
        std::fs::write(here.join(&name), b"x").unwrap();
        let found = find_backing(&tmp("somewhere.qcow2"), &name);
        std::fs::remove_file(here.join(&name)).unwrap();
        assert_eq!(found, None);
        std::fs::write(tmp("next-to-it.img"), b"x").unwrap();
        assert_eq!(find_backing(&tmp("somewhere.qcow2"), "next-to-it.img"), Some(tmp("next-to-it.img")));
        assert_eq!(find_backing(&tmp("somewhere.qcow2"), r"C:\vms\next-to-it.img"), Some(tmp("next-to-it.img")));
    }

    #[test]
    fn a_loop_of_backing_files_ends() {
        let cs = 1usize << 12;
        let mut a = Build::new(12, vec![Cl::Hole, Cl::Data(pattern(1, cs))]);
        a.backing = Some(("loop-b.qcow2".to_string(), None));
        a.write(&tmp("loop-a.qcow2"));
        let mut b = Build::new(12, vec![Cl::Hole, Cl::Hole]);
        b.backing = Some(("loop-a.qcow2".to_string(), None));
        b.write(&tmp("loop-b.qcow2"));
        let e = Qcow2Reader::open(tmp("loop-a.qcow2").to_str().unwrap()).err().unwrap();
        assert!(e.contains("loop"), "{e}");
    }

    #[test]
    fn a_truncated_image_does_not_panic() {
        let cs = 1usize << 12;
        let p = tmp("whole.qcow2");
        Build::new(12, vec![Cl::Data(pattern(1, cs)), Cl::Packed(text(2, cs)), Cl::Data(pattern(3, cs))]).write(&p);
        let bytes = std::fs::read(&p).unwrap();
        for cut in [100usize, cs + 4, 2 * cs + 8, 3 * cs + 10, bytes.len() - cs - 1, bytes.len() - 10] {
            let q = tmp(&format!("cut-{cut}.qcow2"));
            std::fs::write(&q, &bytes[..cut]).unwrap();
            if let Ok(mut r) = Qcow2Reader::open(q.to_str().unwrap()) {
                let mut out = Vec::new();
                let _ = r.read_to_end(&mut out);
            }
        }
    }

    /// Real images against the raw disk they were converted from: set
    /// `MASSTIN_QCOW2_DIR` to a folder of `<name>.<variant>.qcow2` files with
    /// `<name>.raw` next to them (made with `qemu-img convert`).
    #[test]
    fn real_images_match_their_raw_disk() {
        let Ok(dir) = std::env::var("MASSTIN_QCOW2_DIR") else { return };
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".qcow2") || name.contains(".base.") {
                continue;
            }
            let stem = name.split('.').next().unwrap();
            let raw = std::fs::read(Path::new(&dir).join(format!("{stem}.raw"))).unwrap();
            let mut r = Qcow2Reader::open(path.to_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(r.total_size(), raw.len() as u64, "{name}: size");
            let mut got = Vec::new();
            r.read_to_end(&mut got).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(got == raw, "{name}: content differs from {stem}.raw");
            // and in pieces that do not line up with anything
            for (from, len) in [(1usize, 70_001usize), (raw.len() / 2 - 13, 300_007), (raw.len() - 5000, 5000)] {
                let mut buf = vec![0u8; len];
                r.seek(SeekFrom::Start(from as u64)).unwrap();
                r.read_exact(&mut buf).unwrap();
                assert!(buf[..] == raw[from..from + len], "{name}: piece at {from}");
            }
            seen += 1;
        }
        assert!(seen > 0, "no .qcow2 in {dir}");
    }
}
