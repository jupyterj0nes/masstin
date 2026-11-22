//! What a disk image is, by what it holds rather than by what it is called.
//!
//! A disk image does not always carry an image extension: a cloud snapshot
//! exported as `snap-web01_os_disk-20261116`, a copy renamed `.bin`, a fixed
//! VHD named `.dd`. Whatever the name, the first 4 KiB and the last 512 bytes
//! say what it is: a container by its magic (EWF, VHDX, VHD, sparse VMDK) or
//! a raw copy of a disk or a volume by what a disk or a volume starts with
//! (a GPT header, an MBR with a valid partition entry, an NTFS boot sector,
//! an ext2/3/4 or XFS superblock, an LVM label). The same check as Faramir's.
//!
//! Only files that could be an image are looked into: 64 KiB at least, and
//! not named as something else (an EVTX, an archive, a text log, a hive...),
//! so a big evidence folder costs a read of 4.5 KiB for the few files whose
//! name says nothing.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// The reader an image opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// EnCase / Expert Witness (`.E01`, `.Ex01`)
    Ewf,
    /// VMware virtual disk (descriptor or monolithic sparse extent)
    Vmdk,
    /// Microsoft virtual disk: VHD (fixed, dynamic, differencing)
    Vhd,
    /// Microsoft virtual disk: VHDX
    Vhdx,
    /// A plain byte-for-byte copy of a disk or a volume
    Raw,
}

impl ImageKind {
    /// What the console and the window call it.
    pub fn label(self) -> &'static str {
        match self {
            ImageKind::Ewf => "E01",
            ImageKind::Vmdk => "VMDK",
            ImageKind::Vhd => "VHD",
            ImageKind::Vhdx => "VHDX",
            ImageKind::Raw => "raw",
        }
    }
}

/// Smallest file the content check considers: no disk or volume is smaller.
pub const SNIFF_MIN_SIZE: u64 = 64 * 1024;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";

/// The kind of disk image the first 4 KiB and the last 512 bytes of a file
/// show. `None` when nothing says disk image.
pub fn image_kind_from_bytes(head: &[u8], tail: &[u8]) -> Option<ImageKind> {
    image_kind_from_bytes_of(head, tail, u64::MAX)
}

/// [`image_kind_from_bytes`] for a file of `len` bytes: a partition of an
/// MBR has to start inside the file.
pub fn image_kind_from_bytes_of(head: &[u8], tail: &[u8], len: u64) -> Option<ImageKind> {
    if head.len() < 4096 {
        return None;
    }
    if head.starts_with(b"EVF\x09\x0d\x0a\xff\x00") || head.starts_with(b"EVF2\x0d\x0a\x81\x00") {
        return Some(ImageKind::Ewf);
    }
    if head.starts_with(b"vhdxfile") {
        return Some(ImageKind::Vhdx);
    }
    // a dynamic VHD has its footer copy at the start, a fixed one (as Azure
    // and Hyper-V export them) only at the end
    if head.starts_with(b"conectix") || tail.starts_with(b"conectix") {
        return Some(ImageKind::Vhd);
    }
    if head.starts_with(b"KDMV") {
        return Some(ImageKind::Vmdk);
    }
    let boot_signature = head[510] == 0x55 && head[511] == 0xAA;
    if boot_signature && &head[512..520] == b"EFI PART" {
        return Some(ImageKind::Raw);
    }
    if boot_signature {
        let valid_entry = (0..4).any(|i| {
            let e = &head[446 + 16 * i..446 + 16 * (i + 1)];
            let start = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
            let sectors = u32::from_le_bytes([e[12], e[13], e[14], e[15]]);
            (e[0] == 0x00 || e[0] == 0x80) && e[4] != 0 && start != 0 && sectors != 0 && (start as u64) * 512 < len
        });
        if valid_entry {
            return Some(ImageKind::Raw);
        }
    }
    if &head[3..11] == NTFS_SIGNATURE {
        return Some(ImageKind::Raw);
    }
    // an ext2/3/4 superblock: its magic, and fields that only a superblock
    // has in range (two bytes alone are in one file out of 65,536)
    if head[1080] == 0x53 && head[1081] == 0xEF {
        let le32 = |o: usize| u32::from_le_bytes([head[o], head[o + 1], head[o + 2], head[o + 3]]);
        let (inodes, blocks, log_block, per_group, inodes_per_group, rev) = (le32(1024), le32(1028), le32(1024 + 24), le32(1024 + 32), le32(1024 + 40), le32(1024 + 76));
        if inodes > 0 && blocks > 0 && log_block <= 6 && per_group > 0 && inodes_per_group > 0 && rev <= 1 {
            return Some(ImageKind::Raw);
        }
    }
    if head.starts_with(b"XFSB") || &head[512..520] == b"LABELONE" {
        return Some(ImageKind::Raw);
    }
    None
}

/// [`image_kind_from_bytes`] on a file. Files under [`SNIFF_MIN_SIZE`] and
/// files that cannot be read are not disk images.
pub fn sniff(path: &Path) -> Option<ImageKind> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() < SNIFF_MIN_SIZE {
        return None;
    }
    let mut f = File::open(path).ok()?;
    let mut head = vec![0u8; 4096];
    f.read_exact(&mut head).ok()?;
    let mut tail = vec![0u8; 512];
    f.seek(SeekFrom::End(-512)).ok()?;
    f.read_exact(&mut tail).ok()?;
    image_kind_from_bytes_of(&head, &tail, meta.len())
}

/// Extensions of the files the content check leaves alone: they are
/// something else (logs, archives, documents, databases...) or a piece of
/// an image read through its first segment.
const NOT_IMAGES: &[&str] = &[
    "evtx", "etl", "evt", "zip", "7z", "rar", "gz", "tgz", "tar", "bz2", "xz", "zst", "lz4", "cab", "csv", "tsv", "json", "ndjson", "jsonl", "log", "txt", "xml", "html", "htm",
    "md", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "mdb", "edb", "db", "sqlite", "sqlite3", "dat", "hve", "reg", "pf", "lnk", "exe", "dll", "sys", "msi",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "mp4", "mp3", "avi", "mkv", "mov", "wav", "journal", "masstin", "plist", "yaml", "yml", "toml", "ini", "cfg", "conf",
    "py", "rs", "js", "ts", "c", "h", "go", "java", "class", "jar", "pcap", "pcapng", "lime", "mem", "dmp", "hiberfil", "pagefile", "iso", "ova", "ovf", "vdi", "qcow2",
    "avhdx", "avhd", "mf", "nvram", "vmsn", "vmem", "vmss", "vmx", "vmxf", "vmsd", "ctk",
];

/// Whether the file's name leaves the question open: no extension, or one
/// that names neither an image nor anything else.
pub fn worth_sniffing(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    if name.ends_with(".journal~") {
        return false;
    }
    // a Linux log by its own name (`secure-20261101`, `wtmp.1`, `lastlog`,
    // `messages`): binary ones hold any bytes
    let family = crate::parse_linux::log_family(&name);
    if family != "other" && crate::detect::is_rotated_log_name(&name, family) {
        return false;
    }
    let ext = match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() => e,
        _ => return true,
    };
    if NOT_IMAGES.contains(&ext) {
        return false;
    }
    // EWF segments after the first, split-raw pieces after the first (.002…)
    let b = ext.as_bytes();
    let ewf_segment = (b.len() == 3 && b[0] == b'e' && b[1].is_ascii_digit() && b[2].is_ascii_alphanumeric())
        || (b.len() == 4 && b[0] == b'e' && b[1] == b'x' && b[2].is_ascii_alphanumeric() && b[3].is_ascii_alphanumeric());
    if ewf_segment {
        return false;
    }
    if b.len() == 3 && b.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

/// A disk image by its content, for a file whose name says nothing.
pub fn by_content(path: &Path) -> bool {
    worth_sniffing(path) && sniff(path).is_some()
}

/// The reader to open an image with: its content when the content names a
/// container format, else its name, else a raw copy. A `.vhd` that is a
/// plain raw disk opens as raw; a fixed VHD named `.dd`, or with no
/// extension, opens as a VHD.
pub fn kind_of(path: &Path) -> ImageKind {
    let sniffed = sniff(path);
    if let Some(k @ (ImageKind::Ewf | ImageKind::Vhd | ImageKind::Vhdx | ImageKind::Vmdk | ImageKind::Raw)) = sniffed {
        return k;
    }
    let lower = path.to_string_lossy().to_lowercase();
    if lower.ends_with(".e01") || lower.ends_with(".ex01") {
        ImageKind::Ewf
    } else if lower.ends_with(".vmdk") {
        ImageKind::Vmdk
    } else if lower.ends_with(".vhdx") {
        ImageKind::Vhdx
    } else if lower.ends_with(".vhd") {
        ImageKind::Vhd
    } else {
        ImageKind::Raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> Vec<u8> {
        vec![0u8; 4096]
    }

    /// Every format by its own bytes, whatever the file is called.
    #[test]
    fn each_format_by_its_bytes() {
        let tail = vec![0u8; 512];
        let mut h = block();
        h[..8].copy_from_slice(b"EVF\x09\x0d\x0a\xff\x00");
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Ewf));
        let mut h = block();
        h[..8].copy_from_slice(b"vhdxfile");
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Vhdx));
        let mut t = tail.clone();
        t[..8].copy_from_slice(b"conectix");
        assert_eq!(image_kind_from_bytes(&block(), &t), Some(ImageKind::Vhd), "a fixed VHD: its footer at the end");
        let mut h = block();
        h[..4].copy_from_slice(b"KDMV");
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Vmdk));
        // a GPT disk
        let mut h = block();
        h[510] = 0x55;
        h[511] = 0xAA;
        h[512..520].copy_from_slice(b"EFI PART");
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Raw));
        // an MBR disk with one partition
        let mut h = block();
        h[510] = 0x55;
        h[511] = 0xAA;
        h[446 + 4] = 0x07;
        h[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        h[446 + 12..446 + 16].copy_from_slice(&100_000u32.to_le_bytes());
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Raw));
        // the same table in a file the partition does not fit in is not a disk
        assert_eq!(image_kind_from_bytes_of(&h, &tail, 512 * 1024), None);
        assert_eq!(image_kind_from_bytes_of(&h, &tail, 64 << 20), Some(ImageKind::Raw));
        // a boot signature and no partition is not a disk
        let mut h = block();
        h[510] = 0x55;
        h[511] = 0xAA;
        assert_eq!(image_kind_from_bytes(&h, &tail), None);
        // volumes: NTFS, ext, XFS, LVM
        let mut h = block();
        h[3..11].copy_from_slice(NTFS_SIGNATURE);
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Raw));
        let mut h = block();
        h[1080] = 0x53;
        h[1081] = 0xEF;
        assert_eq!(image_kind_from_bytes(&h, &tail), None, "the magic alone is not a superblock");
        h[1024..1028].copy_from_slice(&65_536u32.to_le_bytes()); // inodes
        h[1028..1032].copy_from_slice(&262_144u32.to_le_bytes()); // blocks
        h[1048..1052].copy_from_slice(&2u32.to_le_bytes()); // 4 KiB blocks
        h[1056..1060].copy_from_slice(&32_768u32.to_le_bytes()); // blocks per group
        h[1064..1068].copy_from_slice(&8_192u32.to_le_bytes()); // inodes per group
        h[1100..1104].copy_from_slice(&1u32.to_le_bytes()); // revision
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Raw));
        let mut h = block();
        h[..4].copy_from_slice(b"XFSB");
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Raw));
        let mut h = block();
        h[512..520].copy_from_slice(b"LABELONE");
        assert_eq!(image_kind_from_bytes(&h, &tail), Some(ImageKind::Raw));
        // anything else, and too little to tell
        assert_eq!(image_kind_from_bytes(&block(), &tail), None);
        assert_eq!(image_kind_from_bytes(&[0u8; 100], &tail), None);
    }

    /// Only names that leave the question open are looked into.
    #[test]
    fn names_that_say_something_else_are_not_looked_into() {
        for n in ["snap-web01_os_disk-20261116", "disk.bin", "server.disk", "copy.2026-11-16", "x.dd.renamed"] {
            assert!(worth_sniffing(Path::new(n)), "{}", n);
        }
        for n in ["Security.evtx", "triage.zip", "uac.tar.gz", "auth.log", "system@x.journal", "system@x.journal~", "case.E02", "case.Ex02", "split.002", "NTUSER.DAT", "t.csv", "wtmp", "btmp-20261101", "lastlog", "secure", "messages-20261101", "auth.log.1"] {
            assert!(!worth_sniffing(Path::new(n)), "{}", n);
        }
    }

    /// A file on disk: an extensionless fixed VHD is a VHD, an extensionless
    /// raw disk is raw, a small or unknown file is nothing; the reader
    /// follows the content before the name.
    #[test]
    fn files_on_disk() {
        let dir = std::env::temp_dir().join(format!("masstin_image_kind_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut vhd = vec![0u8; 128 * 1024];
        let n = vhd.len();
        vhd[n - 512..n - 504].copy_from_slice(b"conectix");
        let p = dir.join("snap-web01_os_disk-20261116");
        std::fs::write(&p, &vhd).unwrap();
        assert!(by_content(&p));
        assert_eq!(kind_of(&p), ImageKind::Vhd);
        // the search for images and the wizard's look take it
        assert!(crate::parse_image_windows::is_first_image_segment(&p));
        let s = crate::detect::scan(&[dir.to_string_lossy().to_string()], crate::detect::Limits::QUICK);
        assert_eq!(s.images.len(), 1, "{:?}", s.images);
        // the same bytes named .dd open as a VHD
        let q = dir.join("web01.dd");
        std::fs::write(&q, &vhd).unwrap();
        assert_eq!(kind_of(&q), ImageKind::Vhd);
        let mut raw = vec![0u8; 128 * 1024];
        raw[3..11].copy_from_slice(NTFS_SIGNATURE);
        let r = dir.join("volume.bin");
        std::fs::write(&r, &raw).unwrap();
        assert!(by_content(&r));
        assert_eq!(kind_of(&r), ImageKind::Raw);
        let small = dir.join("tiny");
        std::fs::write(&small, &raw[..1024]).unwrap();
        assert!(!by_content(&small), "under 64 KiB");
        let other = dir.join("notes");
        std::fs::write(&other, vec![b'x'; 100_000]).unwrap();
        assert!(!by_content(&other));
        // a named image whose content says nothing keeps its name's reader
        let e01 = dir.join("case.E01");
        std::fs::write(&e01, vec![0u8; 100]).unwrap();
        assert_eq!(kind_of(&e01), ImageKind::Ewf);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
