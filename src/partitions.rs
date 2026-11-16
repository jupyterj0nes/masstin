//! What the two image readers (Windows and Linux volumes) share about
//! partition tables: the sector size of a GPT disk and the logical
//! partitions of an MBR.
//!
//! Both readers took a sector for 512 bytes and looked at the four primary
//! entries of an MBR only. A disk with 4096-byte sectors (4Kn: most
//! enterprise disks since 2015, every large NVMe namespace formatted so)
//! has its GPT header at byte 4096 and its partitions at `LBA x 4096`: it
//! read as "no partitions". And a volume inside an extended partition
//! (`/var`, `/home` or a data volume on older Linux and Windows installs)
//! was never looked at.

use std::io::{Read, Seek, SeekFrom};

/// The sector sizes disks are made with.
pub(crate) const SECTOR_SIZES: [u64; 2] = [512, 4096];

/// The sector size of a GPT disk: the size that puts the `EFI PART`
/// header at LBA 1. None when there is no GPT header at either place.
pub(crate) fn gpt_sector_size<R: Read + Seek>(reader: &mut R) -> Option<u64> {
    for size in SECTOR_SIZES {
        let mut sig = [0u8; 8];
        if reader.seek(SeekFrom::Start(size)).is_ok() && reader.read_exact(&mut sig).is_ok() && &sig == b"EFI PART" {
            return Some(size);
        }
    }
    None
}

/// MBR partition types that hold other partitions (an extended partition).
fn is_extended(part_type: u8) -> bool {
    matches!(part_type, 0x05 | 0x0F | 0x85)
}

/// The logical partitions of an MBR, as `(type, first LBA)`: the chain of
/// extended boot records inside each extended partition. Each record has
/// the logical partition it introduces (its start relative to the record)
/// and the next record (relative to the start of the extended partition).
/// A chain that loops or runs off the disk ends there.
pub(crate) fn mbr_logical_partitions<R: Read + Seek>(reader: &mut R, mbr: &[u8; 512], sector: u64) -> Vec<(u8, u64)> {
    let mut out = Vec::new();
    for i in 0..4 {
        let e = 446 + i * 16;
        if !is_extended(mbr[e + 4]) {
            continue;
        }
        let ext_start = u32::from_le_bytes([mbr[e + 8], mbr[e + 9], mbr[e + 10], mbr[e + 11]]) as u64;
        if ext_start == 0 {
            continue;
        }
        let mut ebr = ext_start;
        let mut seen = std::collections::HashSet::new();
        // (a disk has a handful of logical partitions; a chain longer than
        // this is a damaged or hostile table)
        while seen.insert(ebr) && seen.len() <= 128 {
            let mut buf = [0u8; 512];
            if reader.seek(SeekFrom::Start(ebr.saturating_mul(sector))).is_err() || reader.read_exact(&mut buf).is_err() || buf[510] != 0x55 || buf[511] != 0xAA {
                break;
            }
            let part_type = buf[446 + 4];
            let rel = u32::from_le_bytes([buf[446 + 8], buf[446 + 9], buf[446 + 10], buf[446 + 11]]) as u64;
            if part_type != 0 && rel != 0 {
                out.push((part_type, ebr + rel));
            }
            let next_type = buf[462 + 4];
            let next_rel = u32::from_le_bytes([buf[462 + 8], buf[462 + 9], buf[462 + 10], buf[462 + 11]]) as u64;
            if !is_extended(next_type) || next_rel == 0 {
                break;
            }
            ebr = ext_start + next_rel;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn entry(buf: &mut [u8], slot: usize, part_type: u8, lba: u32, sectors: u32) {
        let e = 446 + slot * 16;
        buf[e + 4] = part_type;
        buf[e + 8..e + 12].copy_from_slice(&lba.to_le_bytes());
        buf[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
        buf[510] = 0x55;
        buf[511] = 0xAA;
    }

    #[test]
    fn the_gpt_header_says_the_sector_size() {
        for size in [512usize, 4096] {
            let mut disk = vec![0u8; 3 * 4096];
            disk[size..size + 8].copy_from_slice(b"EFI PART");
            assert_eq!(gpt_sector_size(&mut Cursor::new(disk)), Some(size as u64));
        }
        assert_eq!(gpt_sector_size(&mut Cursor::new(vec![0u8; 3 * 4096])), None);
        assert_eq!(gpt_sector_size(&mut Cursor::new(vec![0u8; 100])), None);
    }

    #[test]
    fn logical_partitions_are_found_along_the_chain() {
        // primary at 2048, extended at 10000 holding logicals at 10000+2048
        // and (second record at +5000) 15000+2048
        let mut disk = vec![0u8; 20000 * 512];
        entry(&mut disk[0..512], 0, 0x83, 2048, 4000);
        entry(&mut disk[0..512], 1, 0x05, 10000, 9000);
        let ebr1 = 10000 * 512;
        entry(&mut disk[ebr1..ebr1 + 512], 0, 0x83, 2048, 2000);
        entry(&mut disk[ebr1..ebr1 + 512], 1, 0x05, 5000, 4000);
        let ebr2 = 15000 * 512;
        entry(&mut disk[ebr2..ebr2 + 512], 0, 0x07, 2048, 1000);
        let mbr: [u8; 512] = disk[0..512].try_into().unwrap();
        assert_eq!(mbr_logical_partitions(&mut Cursor::new(disk), &mbr, 512), vec![(0x83, 12048), (0x07, 17048)]);
    }

    #[test]
    fn a_chain_that_loops_or_leaves_the_disk_ends() {
        let mut disk = vec![0u8; 12000 * 512];
        entry(&mut disk[0..512], 0, 0x0F, 10000, 1000);
        let ebr = 10000 * 512;
        entry(&mut disk[ebr..ebr + 512], 0, 0x83, 100, 100);
        // the next record is this one again
        entry(&mut disk[ebr..ebr + 512], 1, 0x05, 0, 0);
        disk[ebr + 462 + 8..ebr + 462 + 12].copy_from_slice(&0u32.to_le_bytes());
        let mbr: [u8; 512] = disk[0..512].try_into().unwrap();
        assert_eq!(mbr_logical_partitions(&mut Cursor::new(disk.clone()), &mbr, 512), vec![(0x83, 10100)]);
        // a record that points back to the start of the extended partition: a loop
        let mut looped = disk.clone();
        entry(&mut looped[ebr..ebr + 512], 1, 0x05, 0, 1);
        looped[ebr + 462 + 8..ebr + 462 + 12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(mbr_logical_partitions(&mut Cursor::new(looped), &mbr, 512).len(), 1);
        // an extended partition beyond the end of the image
        let mut far = vec![0u8; 1024];
        entry(&mut far[0..512], 0, 0x05, 900_000, 10);
        let mbr: [u8; 512] = far[0..512].try_into().unwrap();
        assert!(mbr_logical_partitions(&mut Cursor::new(far), &mbr, 512).is_empty());
    }
}
