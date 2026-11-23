//! The Linux logs of a disk image, read where they are.
//!
//! The Linux half reads its logs by path: the logs of a triage folder, of a
//! package unpacked, and those of a disk image. For an image they used to be
//! copied first to a temporary folder laid out like the volume's root
//! (`.../linux_logs_extracted/partition_0/var/log/secure`), and read from
//! there: gigabytes written to be read once. Now the image's volume is only
//! *looked at* when the image is extracted: the files that would have been
//! copied are listed (their path in the volume, their size and time) under
//! the folder they would have been copied to, which is never written. When
//! the Linux half asks for a path under that folder, the image is opened
//! again and the file is read from the volume (ext4 or XFS, in a partition
//! or in an LVM logical volume), a piece at a time. Everything else (a
//! triage, a package, a log on disk) is read from the disk as before. The
//! paths, and so the order the logs are read in and the names the timeline
//! gives them, are the ones the copies had.
//!
//! The time of a file is its time in the volume: the copies' was the time
//! they were made, so a syslog with no year and no other clue took the year
//! of the run; it now takes the year the file was last written.
//!
//! The EVTX of a Windows image are read the same way: listed under
//! `.../evtx_extracted/partition_0` (and `partition_0_vss_2` for those of a
//! shadow copy) when the image is looked at, and read from NTFS (through
//! the shadow copy's store for those) when the Windows half opens them.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A file system of an image's volume: what it is and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    pub image: String,
    pub fs: VolumeFs,
    /// the partition's offset in the image, or the LVM physical volume's
    pub offset: u64,
    /// the logical volume, for a volume inside LVM
    pub lv: Option<String>,
    /// the shadow copy's store, for an NTFS volume as a shadow copy has it
    pub vss: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeFs {
    Ext4,
    Xfs,
    /// a file is named by its record number in the MFT
    Ntfs,
}

/// One file of a volume, under the folder it would have been copied to.
#[derive(Clone, Debug)]
struct Listed {
    /// its path in the volume
    src: String,
    len: u64,
    modified: Option<SystemTime>,
}

/// The folder a volume's files would have been copied to, and its files
/// (by their path relative to that folder).
struct Placed {
    root: PathBuf,
    volume: Volume,
    files: BTreeMap<PathBuf, Listed>,
}

static PLACED: Mutex<Vec<Placed>> = Mutex::new(Vec::new());

thread_local! {
    /// the image whose volumes are being looked at on this thread (set by
    /// the image readers; unset, the logs are copied as before)
    static IMAGE: RefCell<Option<String>> = const { RefCell::new(None) };
    /// the volumes opened on this thread, the last ones used
    static MOUNTED: RefCell<Vec<(PathBuf, Rc<Mounted>)>> = const { RefCell::new(Vec::new()) };
}

use std::rc::Rc;

/// While `f` runs, the Linux volumes found in `image` are listed, not copied.
pub fn with_image<T>(image: &str, f: impl FnOnce() -> T) -> T {
    let before = IMAGE.with(|i| i.replace(Some(image.to_string())));
    let out = f();
    IMAGE.with(|i| *i.borrow_mut() = before);
    out
}

/// The image being read on this thread, if its volumes are to be listed.
pub fn current_image() -> Option<String> {
    IMAGE.with(|i| i.borrow().clone())
}

/// A file of `volume` (`src`, its path there) listed under `dest`, the path
/// its copy would have had; `root` is the folder of the volume's copies.
pub fn list(root: &Path, volume: &Volume, dest: &Path, src: &str, len: u64, modified: Option<SystemTime>) {
    let Ok(rel) = dest.strip_prefix(root) else { return };
    let mut placed = PLACED.lock().unwrap_or_else(|e| e.into_inner());
    let i = match placed.iter().position(|p| p.root == root) {
        Some(i) => i,
        None => {
            placed.push(Placed { root: root.to_path_buf(), volume: volume.clone(), files: BTreeMap::new() });
            placed.len() - 1
        }
    };
    placed[i].files.insert(rel.to_path_buf(), Listed { src: src.to_string(), len, modified });
}

/// Forget the volumes listed under `under` (the run's temporary folder),
/// at the end of a run.
pub fn forget(under: &Path) {
    PLACED.lock().unwrap_or_else(|e| e.into_inner()).retain(|p| !p.root.starts_with(under));
    MOUNTED.with(|m| m.borrow_mut().retain(|(r, _)| !r.starts_with(under)));
}

/// The EVTX listed under `under` are no longer listed (they have been
/// read); the Linux logs listed there stay.
pub fn forget_evtx(under: &Path) {
    PLACED.lock().unwrap_or_else(|e| e.into_inner()).retain(|p| !(p.volume.fs == VolumeFs::Ntfs && p.root.starts_with(under)));
    MOUNTED.with(|m| m.borrow_mut().retain(|(r, m)| !(matches!(**m, Mounted::Ntfs(_)) && r.starts_with(under))));
}

/// Is `p` a file listed from a volume (not a file on disk)?
pub fn listed(p: &Path) -> bool {
    placed_for(p).map_or(false, |(_, _, file, _)| file.is_some())
}

/// The listed volume a path falls under: its folder, the volume, and the
/// file (when the path is one of its files).
fn placed_for(p: &Path) -> Option<(PathBuf, Volume, Option<Listed>, bool)> {
    let placed = PLACED.lock().unwrap_or_else(|e| e.into_inner());
    let pl = placed.iter().filter(|pl| p.starts_with(&pl.root)).max_by_key(|pl| pl.root.as_os_str().len())?;
    let rel = p.strip_prefix(&pl.root).ok()?;
    let file = pl.files.get(rel).cloned();
    // a folder: the root or a folder some listed file is under
    let is_dir = file.is_none() && (rel.as_os_str().is_empty() || pl.files.keys().any(|k| k.starts_with(rel) && k != rel));
    Some((pl.root.clone(), pl.volume.clone(), file, is_dir))
}

/// What `metadata` answers.
#[derive(Clone, Copy, Debug)]
pub struct Meta {
    len: u64,
    modified: Option<SystemTime>,
    is_file: bool,
    is_dir: bool,
}

impl Meta {
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn modified(&self) -> io::Result<SystemTime> {
        self.modified.ok_or_else(|| io::Error::other("no time"))
    }
    pub fn is_file(&self) -> bool {
        self.is_file
    }
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
}

fn not_found(p: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{}: not in the volume", p.display()))
}

pub fn metadata(p: &Path) -> io::Result<Meta> {
    if let Some((_, _, file, is_dir)) = placed_for(p) {
        return match file {
            Some(f) => Ok(Meta { len: f.len, modified: f.modified, is_file: true, is_dir: false }),
            None if is_dir => Ok(Meta { len: 0, modified: None, is_file: false, is_dir: true }),
            None => Err(not_found(p)),
        };
    }
    let m = std::fs::metadata(p)?;
    Ok(Meta { len: m.len(), modified: m.modified().ok(), is_file: m.is_file(), is_dir: m.is_dir() })
}

pub fn exists(p: &Path) -> bool {
    metadata(p).is_ok()
}

pub fn is_file(p: &Path) -> bool {
    metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// What a file is read through.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// The file at `p`: from its volume when it is a listed one, else from disk.
pub fn open(p: &Path) -> io::Result<Box<dyn ReadSeek>> {
    if let Some((root, volume, file, _)) = placed_for(p) {
        let f = file.ok_or_else(|| not_found(p))?;
        let m = mount(&root, &volume)?;
        return Ok(Box::new(Paged::new(m.open(&f.src)?, f.len)));
    }
    Ok(Box::new(std::fs::File::open(p)?))
}

pub fn read(p: &Path) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    open(p)?.read_to_end(&mut v)?;
    Ok(v)
}

/// The pieces of the file at `p` that hold something, each with where it
/// starts in the file, and whether there was more than `most` bytes of them
/// (the rest is then not read). A file may be all holes around a few
/// blocks (a lastlog has a slot per uid: 500 GB of nothing with the uids
/// of a directory): read from start to end that is minutes of zeros, read
/// by the file's own map it is its few blocks. None for a file that is not
/// of a volume, and where the map is not one this reads (the caller then
/// reads the file as any other).
pub fn data_pieces(p: &Path, most: u64) -> io::Result<Option<(Vec<(u64, Vec<u8>)>, bool)>> {
    let Some((root, volume, file, _)) = placed_for(p) else { return Ok(None) };
    let f = file.ok_or_else(|| not_found(p))?;
    let m = mount(&root, &volume)?;
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut held = 0u64;
    match &*m {
        Mounted::Ext4(_, raw) => {
            let mut raw = raw.borrow_mut();
            let Some((bs, extents)) = ext4_map(&mut **raw, &f.src) else { return Ok(None) };
            for (logical, len, physical) in extents {
                let start = logical.saturating_mul(bs);
                if start >= f.len {
                    continue;
                }
                let n = len.saturating_mul(bs).min(f.len - start);
                if held + n > most {
                    return Ok(Some((out, true)));
                }
                let mut buf = vec![0u8; n as usize];
                raw.read(physical * bs, &mut buf).map_err(io::Error::other)?;
                held += n;
                out.push((start, buf));
            }
            Ok(Some((out, false)))
        }
        Mounted::Xfs(fs) => {
            let Ok(file) = fs.open(&f.src) else { return Ok(None) };
            let (inode, raw) = (file.inode().clone(), file.raw().to_vec());
            let Ok(extents) = fs.data_extents(&inode, &raw) else { return Ok(None) };
            let bs = u64::from(fs.superblock().blocksize);
            for e in extents {
                let start = e.startoff.saturating_mul(bs);
                if e.unwritten || start >= f.len {
                    continue;
                }
                let n = e.blockcount.saturating_mul(bs).min(f.len - start);
                if held + n > most {
                    return Ok(Some((out, true)));
                }
                let mut buf = vec![0u8; n as usize];
                let mut got = 0usize;
                while got < buf.len() {
                    let k = fs.read_at(&inode, &raw, start + got as u64, &mut buf[got..]).map_err(|e| io::Error::other(e.to_string()))?;
                    if k == 0 {
                        break;
                    }
                    got += k;
                }
                buf.truncate(got);
                held += n;
                out.push((start, buf));
            }
            Ok(Some((out, false)))
        }
        Mounted::Ntfs(_) => Ok(None),
    }
}

/// The map of the ext4 file at `path` (from the root of its volume): the
/// size of a block and, for each extent written, the block of the file it
/// starts at, its blocks and the block of the volume it lies at. Read from
/// the volume itself: the driver gives a file block after block, holes
/// included, and says nothing of where they are. None for what this does
/// not read (no extents, meta_bg, a link on the way, anything that does
/// not look as it should).
fn ext4_map(dev: &mut dyn ext4_view::Ext4Read, path: &str) -> Option<(u64, Vec<(u64, u64, u64)>)> {
    fn rd(dev: &mut dyn ext4_view::Ext4Read, at: u64, len: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; len];
        dev.read(at, &mut b).ok()?;
        Some(b)
    }
    let le16 = |b: &[u8], at: usize| u64::from(u16::from_le_bytes([b[at], b[at + 1]]));
    let le32 = |b: &[u8], at: usize| u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]));

    let sb = rd(dev, 1024, 1024)?;
    if le16(&sb, 0x38) != 0xEF53 {
        return None;
    }
    let log_bs = le32(&sb, 0x18);
    if log_bs > 6 {
        return None;
    }
    let bs = 1024u64 << log_bs;
    let first_data_block = le32(&sb, 0x14);
    let inodes_per_group = le32(&sb, 0x28);
    let inode_size = if le32(&sb, 0x4C) >= 1 { le16(&sb, 0x58) } else { 128 };
    let incompat = le32(&sb, 0x60);
    if incompat & 0x10 != 0 || inodes_per_group == 0 || inode_size < 128 || inode_size > bs {
        return None; // meta_bg: the group descriptors are elsewhere
    }
    let desc_size = if incompat & 0x80 != 0 { le16(&sb, 0xFE).max(32) } else { 32 };

    // the inode `n`: (mode, flags, its 60 bytes of map)
    let inode = |dev: &mut dyn ext4_view::Ext4Read, n: u64| -> Option<(u64, u64, Vec<u8>)> {
        if n == 0 {
            return None;
        }
        let (group, index) = ((n - 1) / inodes_per_group, (n - 1) % inodes_per_group);
        let d = rd(dev, (first_data_block + 1) * bs + group * desc_size, desc_size as usize)?;
        let table = le32(&d, 8) | if desc_size >= 64 { le32(&d, 0x28) << 32 } else { 0 };
        let i = rd(dev, table.checked_mul(bs)? + index * inode_size, 128)?;
        Some((le16(&i, 0), le32(&i, 0x20), i[0x28..0x28 + 60].to_vec()))
    };

    // the extents under a node of the tree, into `out`
    fn walk(dev: &mut dyn ext4_view::Ext4Read, node: &[u8], bs: u64, level: u32, out: &mut Vec<(u64, u64, u64)>) -> Option<()> {
        let le16 = |b: &[u8], at: usize| u64::from(u16::from_le_bytes([b[at], b[at + 1]]));
        let le32 = |b: &[u8], at: usize| u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]));
        if node.len() < 12 || le16(node, 0) != 0xF30A || level > 6 {
            return None;
        }
        let (entries, depth) = (le16(node, 2) as usize, le16(node, 6));
        if 12 + entries * 12 > node.len() {
            return None;
        }
        for i in 0..entries {
            let e = 12 + i * 12;
            if depth == 0 {
                let len = le16(node, e + 4);
                // over 32768: set aside and never written, zeros
                if len <= 32768 {
                    out.push((le32(node, e), len, le32(node, e + 8) | (le16(node, e + 6) << 32)));
                }
            } else {
                let child = le32(node, e + 4) | (le16(node, e + 8) << 32);
                let mut b = vec![0u8; bs as usize];
                dev.read(child.checked_mul(bs)?, &mut b).ok()?;
                walk(dev, &b, bs, level + 1, out)?;
            }
            if out.len() > 1_000_000 {
                return None;
            }
        }
        Some(())
    }
    const EXTENTS: u64 = 0x8_0000;

    let mut at = 2u64; // the root
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (k, name) in parts.iter().enumerate() {
        let (mode, flags, map) = inode(dev, at)?;
        if mode & 0xF000 != 0x4000 || flags & EXTENTS == 0 {
            return None; // not a folder (a link), or one kept another way
        }
        let mut extents = Vec::new();
        walk(dev, &map, bs, 0, &mut extents)?;
        let mut found = None;
        'dir: for (_, len, physical) in extents {
            for b in 0..len.min(1 << 16) {
                let block = rd(dev, (physical + b) * bs, bs as usize)?;
                let mut off = 0usize;
                while off + 8 <= block.len() {
                    let (ino, rec, nlen) = (le32(&block, off), le16(&block, off + 4) as usize, block[off + 6] as usize);
                    if rec < 8 || off + rec > block.len() {
                        break;
                    }
                    if ino != 0 && off + 8 + nlen <= block.len() && &block[off + 8..off + 8 + nlen] == name.as_bytes() {
                        found = Some(ino);
                        break 'dir;
                    }
                    off += rec;
                }
            }
        }
        at = found?;
        if k + 1 == parts.len() {
            let (mode, flags, map) = inode(dev, at)?;
            if mode & 0xF000 != 0x8000 || flags & EXTENTS == 0 {
                return None;
            }
            let mut extents = Vec::new();
            walk(dev, &map, bs, 0, &mut extents)?;
            extents.sort();
            return Some((bs, extents));
        }
    }
    None
}

pub fn read_to_string(p: &Path) -> io::Result<String> {
    let mut s = String::new();
    open(p)?.read_to_string(&mut s)?;
    Ok(s)
}

/// The files and folders under `root` (`root` itself included), at most
/// `max_depth` levels down: what `walkdir` gives for a folder on disk, the
/// listed files and their folders for a volume's folder. `(path, is_file)`.
pub fn walk(root: &Path, max_depth: Option<usize>) -> Vec<(PathBuf, bool)> {
    let placed = {
        let placed = PLACED.lock().unwrap_or_else(|e| e.into_inner());
        placed
            .iter()
            .filter(|pl| pl.root.starts_with(root) || root.starts_with(&pl.root))
            .map(|pl| (pl.root.clone(), pl.files.keys().cloned().collect::<Vec<_>>()))
            .collect::<Vec<_>>()
    };
    let mut out: Vec<(PathBuf, bool)> = Vec::new();
    let depth_of = |p: &Path| p.strip_prefix(root).map(|r| r.components().count()).unwrap_or(usize::MAX);
    let fits = |p: &Path| max_depth.map_or(true, |d| depth_of(p) <= d);
    // on disk (a volume's folder is not there, or is there empty)
    if root.exists() {
        for e in walkdir::WalkDir::new(root).max_depth(max_depth.unwrap_or(usize::MAX)).into_iter().filter_map(Result::ok) {
            out.push((e.path().to_path_buf(), e.file_type().is_file()));
        }
    }
    for (vroot, files) in placed {
        let mut dirs: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        for rel in files {
            let full = vroot.join(&rel);
            if !full.starts_with(root) {
                continue;
            }
            let mut d = full.parent();
            while let Some(dir) = d {
                if !dir.starts_with(root) {
                    break;
                }
                dirs.insert(dir.to_path_buf());
                d = dir.parent();
            }
            if fits(&full) {
                out.push((full, true));
            }
        }
        for d in dirs {
            if fits(&d) && !out.iter().any(|(p, _)| *p == d) {
                out.push((d, false));
            }
        }
    }
    out
}

// ─────────────────────────── a volume, opened ───────────────────────────

/// The image's reader, shared by the views of one volume. Used only by the
/// thread that opened it (the mounts are per thread).
struct Image(Mutex<Box<dyn ReadSeek>>);
// Safety: an image is opened, read and dropped by one thread (MOUNTED is a
// thread local); the readers it holds (an E01 reader keeps an Rc) never
// cross threads.
unsafe impl Send for Image {}
unsafe impl Sync for Image {}

/// A view of the image from `offset` on, with a position of its own.
#[derive(Clone)]
struct View {
    img: Arc<Image>,
    offset: u64,
    pos: u64,
}

impl Read for View {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut r = self.img.0.lock().map_err(|_| io::Error::other("image lock poisoned"))?;
        r.seek(SeekFrom::Start(self.offset + self.pos))?;
        let n = r.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for View {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
            SeekFrom::End(d) => {
                let end = self.img.0.lock().map_err(|_| io::Error::other("image lock poisoned"))?.seek(SeekFrom::End(0))?;
                end.saturating_sub(self.offset).checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?
            }
        };
        Ok(self.pos)
    }
}

/// A logical volume of `pv`, read in place (see parse_image_linux::LvDevice).
type Lv = crate::parse_image_linux::LvDevice<View>;

/// Positioned reads over anything that reads and seeks and clones cheaply:
/// what ext4 and XFS want.
#[derive(Clone)]
struct At<T: Read + Seek + Clone>(T);
// Safety: as for Image.
unsafe impl<T: Read + Seek + Clone> Send for At<T> {}
unsafe impl<T: Read + Seek + Clone> Sync for At<T> {}

impl<T: Read + Seek + Clone + 'static> ext4_view::Ext4Read for At<T> {
    fn read(&mut self, start: u64, dst: &mut [u8]) -> Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        let boxed = |e: io::Error| -> Box<dyn core::error::Error + Send + Sync + 'static> { Box::new(e) };
        self.0.seek(SeekFrom::Start(start)).map_err(boxed)?;
        self.0.read_exact(dst).map_err(boxed)
    }
}

struct Block<T: Read + Seek + Clone> {
    dev: At<T>,
    size: u64,
}
// Safety: as for Image.
unsafe impl<T: Read + Seek + Clone> Send for Block<T> {}
unsafe impl<T: Read + Seek + Clone> Sync for Block<T> {}

impl<T: Read + Seek + Clone> fs_core::BlockRead for Block<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        let mut d = self.dev.0.clone();
        d.seek(SeekFrom::Start(offset))?;
        d.read_exact(buf)?;
        Ok(())
    }
    fn size_bytes(&self) -> u64 {
        self.size
    }
}

enum Mounted {
    /// the file system, and its device again for what is read by the
    /// file's own map (see `data_pieces`)
    Ext4(ext4_view::Ext4, RefCell<Box<dyn ext4_view::Ext4Read>>),
    Xfs(Arc<fs_xfs::Filesystem>),
    Ntfs(Rc<NtfsMount>),
}

/// An NTFS volume and what it is read through: the partition of the image,
/// or a shadow copy's view of it.
struct NtfsMount {
    dev: RefCell<Box<dyn ReadSeek>>,
    ntfs: ntfs::Ntfs,
}

/// A shadow copy's view of a volume, owning what it reads through.
struct Store {
    // (in the order they must go: the reader first, then what it borrows)
    store: Option<vshadow::VssStoreReader<'static, View>>,
    _vss: Box<vshadow::VssVolume>,
    _view: Box<View>,
}

impl Store {
    fn open(view: View, index: usize) -> io::Result<Store> {
        let mut view = Box::new(view);
        let vss = Box::new(vshadow::VssVolume::new(&mut *view).map_err(|e| io::Error::other(e.to_string()))?);
        // Safety: the reader borrows the volume and the view, both boxed (so
        // they do not move) and owned by the Store, which drops the reader
        // before them; nothing else reaches them while the Store lives.
        let (vss_ref, view_ref): (&'static vshadow::VssVolume, &'static mut View) = unsafe { (&*(&*vss as *const vshadow::VssVolume), &mut *(&mut *view as *mut View)) };
        let store = vss_ref.store_reader(view_ref, index).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Store { store: Some(store), _vss: vss, _view: view })
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.store = None;
    }
}

impl Read for Store {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.store.as_mut().expect("the store's reader").read(buf)
    }
}

impl Seek for Store {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.store.as_mut().expect("the store's reader").seek(pos)
    }
}

/// The unnamed data of an NTFS file, by the file's record number. Each
/// read opens the record again (a kilobyte of the MFT) and goes to the
/// place asked through the file's runs; with the megabyte pages above it,
/// that is once a megabyte.
struct NtfsData {
    m: Rc<NtfsMount>,
    record: u64,
    pos: u64,
    len: u64,
}

impl Read for NtfsData {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ntfs::NtfsReadSeek;
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let err = |e: ntfs::NtfsError| io::Error::other(e.to_string());
        let mut dev = self.m.dev.borrow_mut();
        let file = self.m.ntfs.file(&mut *dev, self.record).map_err(err)?;
        let item = file.data(&mut *dev, "").ok_or_else(|| io::Error::other("the file has no data"))?.map_err(err)?;
        let attr = item.to_attribute().map_err(err)?;
        let mut value = attr.value(&mut *dev).map_err(err)?;
        value.seek(&mut *dev, SeekFrom::Start(self.pos)).map_err(err)?;
        let want = buf.len().min((self.len - self.pos) as usize);
        let n = value.read(&mut *dev, &mut buf[..want]).map_err(err)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for NtfsData {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
            SeekFrom::End(d) => self.len.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
        };
        Ok(self.pos)
    }
}

impl Mounted {
    fn open(&self, src: &str) -> io::Result<Box<dyn ReadSeek>> {
        match self {
            Mounted::Ntfs(m) => {
                let record: u64 = src.parse().map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("not a file record: {}", src)))?;
                let err = |e: ntfs::NtfsError| io::Error::new(io::ErrorKind::NotFound, e.to_string());
                let len = {
                    let mut dev = m.dev.borrow_mut();
                    let file = m.ntfs.file(&mut *dev, record).map_err(err)?;
                    let item = file.data(&mut *dev, "").ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the file has no data"))?.map_err(err)?;
                    let attr = item.to_attribute().map_err(err)?;
                    let value = attr.value(&mut *dev).map_err(err)?;
                    value.len()
                };
                Ok(Box::new(NtfsData { m: Rc::clone(m), record, pos: 0, len }))
            }
            Mounted::Ext4(fs, _) => Ok(Box::new(fs.open(src).map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?)),
            Mounted::Xfs(fs) => {
                let nf = |e: fs_xfs::Error| io::Error::new(io::ErrorKind::NotFound, e.to_string());
                let f = match fs.open(src) {
                    Ok(f) => f,
                    // /var/run is a link to /run on every current distribution
                    Err(e) => match src.strip_prefix("/var/run/") {
                        Some(rest) => fs.open(&format!("/run/{}", rest)).map_err(nf)?,
                        None => return Err(nf(e)),
                    },
                };
                // the inode and its fork, kept: each read goes straight to
                // the extents, with no walk of the path
                let (inode, raw, len) = (f.inode().clone(), f.raw().to_vec(), f.len());
                Ok(Box::new(XfsFile { fs: Arc::clone(fs), inode, raw, pos: 0, len }))
            }
        }
    }
}

/// An XFS file read a piece at a time, by its inode.
struct XfsFile {
    fs: Arc<fs_xfs::Filesystem>,
    inode: fs_xfs::inode::Inode,
    raw: Vec<u8>,
    pos: u64,
    len: u64,
}

impl Read for XfsFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = self.fs.read_at(&self.inode, &self.raw, self.pos, buf).map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// A file of a volume through a cache of its pages. The Linux half reads a
/// text log from start to end, but a systemd journal by jumping around it
/// (hundreds of thousands of seeks), and a seek in the ext4 driver walks
/// the file's blocks again from its first one: a 128 MiB journal read in
/// place would take hours. Here the file is read a page of 1 MiB at a time
/// and the jumps are served from the 64 pages kept (64 MiB at most for a
/// file, whatever its size); the driver sees a read forward, or a seek for
/// a page not kept.
struct Paged {
    inner: Box<dyn ReadSeek>,
    len: u64,
    pos: u64,
    /// where the driver's own position is
    inner_pos: u64,
    pages: std::collections::HashMap<u64, Vec<u8>>,
    /// the pages kept, the oldest used first
    order: std::collections::VecDeque<u64>,
}

const PAGE: u64 = 1 << 20;
const PAGES_KEPT: usize = 64;

impl Paged {
    fn new(inner: Box<dyn ReadSeek>, len: u64) -> Paged {
        Paged { inner, len, pos: 0, inner_pos: 0, pages: std::collections::HashMap::new(), order: std::collections::VecDeque::new() }
    }

    fn page(&mut self, n: u64) -> io::Result<&[u8]> {
        if self.pages.contains_key(&n) {
            if let Some(i) = self.order.iter().position(|&p| p == n) {
                self.order.remove(i);
            }
            self.order.push_back(n);
        } else {
            let start = n * PAGE;
            let want = PAGE.min(self.len.saturating_sub(start)) as usize;
            if self.inner_pos != start {
                self.inner.seek(SeekFrom::Start(start))?;
                self.inner_pos = start;
            }
            let mut buf = vec![0u8; want];
            let mut got = 0usize;
            while got < want {
                let k = self.inner.read(&mut buf[got..])?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            buf.truncate(got);
            self.inner_pos = start + got as u64;
            while self.order.len() >= PAGES_KEPT {
                if let Some(old) = self.order.pop_front() {
                    self.pages.remove(&old);
                }
            }
            self.pages.insert(n, buf);
            self.order.push_back(n);
        }
        Ok(self.pages.get(&n).map(|v| v.as_slice()).unwrap_or(&[]))
    }
}

impl Read for Paged {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let (n, off) = (self.pos / PAGE, (self.pos % PAGE) as usize);
        let page = self.page(n)?;
        if off >= page.len() {
            return Ok(0);
        }
        let k = buf.len().min(page.len() - off);
        buf[..k].copy_from_slice(&page[off..off + k]);
        self.pos += k as u64;
        Ok(k)
    }
}

impl Seek for Paged {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
            SeekFrom::End(d) => self.len.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
        };
        Ok(self.pos)
    }
}

impl Seek for XfsFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
            SeekFrom::End(d) => self.len.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
        };
        Ok(self.pos)
    }
}

/// The volume of the folder `root`, opened on this thread (kept for the
/// next files; the two last volumes used stay open).
fn mount(root: &Path, volume: &Volume) -> io::Result<Rc<Mounted>> {
    if let Some(m) = MOUNTED.with(|m| m.borrow().iter().find(|(r, _)| r == root).map(|(_, m)| Rc::clone(m))) {
        return Ok(m);
    }
    let (reader, _size) = crate::parse_image_linux::open_image_reader(&volume.image).map_err(io::Error::other)?;
    let img = Arc::new(Image(Mutex::new(reader)));
    let view = View { img, offset: volume.offset, pos: 0 };
    let mounted = match &volume.lv {
        None if volume.fs == VolumeFs::Ntfs => {
            // the many small reads of the MFT go through a buffer; a file's
            // megabytes pass it by
            let mut dev: Box<dyn ReadSeek> = match volume.vss {
                None => Box::new(io::BufReader::with_capacity(1 << 16, view)),
                Some(s) => Box::new(io::BufReader::with_capacity(1 << 16, Store::open(view, s)?)),
            };
            let ntfs = ntfs::Ntfs::new(&mut dev).map_err(|e| io::Error::other(e.to_string()))?;
            Mounted::Ntfs(Rc::new(NtfsMount { dev: RefCell::new(dev), ntfs }))
        }
        None => {
            let size = view.clone().seek(SeekFrom::End(0))?;
            open_fs(volume.fs, At(view), size)?
        }
        Some(name) => {
            let lvm = lvm2::Lvm2::open(view.clone()).map_err(|e| io::Error::other(format!("{:?}", e)))?;
            let lvm = Arc::new(lvm);
            let lv = lvm.lvs().find(|l| l.name() == name.as_str()).ok_or_else(|| io::Error::other(format!("LV {} not found", name)))?;
            let size = lv.size_in_extents() * lvm.extent_size();
            let dev: Lv = crate::parse_image_linux::LvDevice::new(Arc::clone(&lvm), name.clone(), view, size);
            open_fs(volume.fs, At(dev), size)?
        }
    };
    let m = Rc::new(mounted);
    MOUNTED.with(|ms| {
        let mut ms = ms.borrow_mut();
        ms.push((root.to_path_buf(), Rc::clone(&m)));
        while ms.len() > 2 {
            ms.remove(0);
        }
    });
    Ok(m)
}

fn open_fs<T: Read + Seek + Clone + 'static>(fs: VolumeFs, dev: At<T>, size: u64) -> io::Result<Mounted> {
    match fs {
        VolumeFs::Ext4 => {
            let raw: Box<dyn ext4_view::Ext4Read> = Box::new(dev.clone());
            Ok(Mounted::Ext4(ext4_view::Ext4::load(Box::new(dev)).map_err(|e| io::Error::other(e.to_string()))?, RefCell::new(raw)))
        }
        VolumeFs::Xfs => {
            let device: Arc<dyn fs_core::BlockRead> = Arc::new(Block { dev, size });
            Ok(Mounted::Xfs(Arc::new(fs_xfs::Filesystem::mount(device).map_err(|e| io::Error::other(e.to_string()))?)))
        }
        VolumeFs::Ntfs => Err(io::Error::other("NTFS is read from a partition, not from a logical volume")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page cache gives the bytes of the file whatever the order they
    /// are asked in, with a seek of the reader under it only for a page it
    /// does not hold.
    #[test]
    fn a_file_read_by_jumps_is_the_file() {
        let data: Vec<u8> = (0..3_500_000u32).map(|i| (i % 251) as u8).collect();
        let mut p = Paged::new(Box::new(io::Cursor::new(data.clone())), data.len() as u64);
        // from start to end
        let mut all = Vec::new();
        p.read_to_end(&mut all).unwrap();
        assert_eq!(all, data);
        // by jumps, across pages and at the end
        for &(at, n) in &[(0u64, 10usize), (1_048_570, 20), (3_499_990, 50), (2_000_000, 4096), (5, 1), (3_500_000, 8)] {
            p.seek(SeekFrom::Start(at)).unwrap();
            let mut buf = vec![0u8; n];
            let mut got = 0;
            while got < n {
                let k = p.read(&mut buf[got..]).unwrap();
                if k == 0 {
                    break;
                }
                got += k;
            }
            let end = (at as usize + n).min(data.len());
            assert_eq!(&buf[..got], &data[(at as usize).min(data.len())..end], "at {}", at);
        }
        assert_eq!(p.seek(SeekFrom::End(-4)).unwrap(), 3_499_996);
        assert!(p.pages.len() <= PAGES_KEPT);
    }

    /// A volume's files are found under the folder their copies would have
    /// had, with their sizes and times; nothing else is there.
    #[test]
    fn listed_files_are_walked_and_described() {
        let root = std::env::temp_dir().join(format!("masstin_vfs_test_{}", std::process::id())).join("linux_logs_extracted").join("partition_0");
        let v = Volume { image: "x.img".into(), fs: VolumeFs::Ext4, offset: 0, lv: None, vss: None };
        let t = time_of(1_700_000_000);
        list(&root, &v, &root.join("var").join("log").join("secure"), "/log/secure", 123, t);
        list(&root, &v, &root.join("etc").join("hostname"), "/etc/hostname", 9, t);
        let m = metadata(&root.join("var").join("log").join("secure")).unwrap();
        assert!(m.is_file() && m.len() == 123 && m.modified().unwrap() == t.unwrap());
        assert!(metadata(&root.join("var")).unwrap().is_dir());
        assert!(metadata(&root.join("var").join("log").join("messages")).is_err());
        assert!(exists(&root.join("etc").join("hostname")) && !exists(&root.join("etc").join("passwd")));
        let w = walk(&root, None);
        let files: Vec<_> = w.iter().filter(|(_, f)| *f).map(|(p, _)| p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/")).collect();
        assert_eq!(files.len(), 2, "{:?}", w);
        assert!(files.contains(&"var/log/secure".to_string()) && files.contains(&"etc/hostname".to_string()));
        // two levels down: /etc/hostname is there, /var/log/secure is not
        let w2 = walk(&root, Some(2));
        assert!(w2.iter().any(|(p, f)| *f && p.ends_with("hostname")) && !w2.iter().any(|(p, _)| p.ends_with("secure")));
        forget(root.parent().unwrap());
        assert!(!exists(&root.join("etc").join("hostname")));
    }
}

/// Seconds since the epoch as a time (negative before 1970).
pub fn time_of(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}
