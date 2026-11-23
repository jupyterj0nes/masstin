//! A raw image, whole or in pieces. A raw image is often written in
//! segments (`disk.001`, `disk.002`, …: FTK Imager, `dd | split`, `dc3dd`),
//! which are the image cut at fixed sizes with nothing added. masstin
//! opened `disk.001` alone: the partition table was there, and anything
//! past the first segment (most of the file system) read as the end of the
//! file. The segments are read here as the one image they are.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A raw image read across its segments.
pub struct RawImage {
    /// each segment, with where it starts in the image and its length
    parts: Vec<(File, u64, u64)>,
    len: u64,
    pos: u64,
}

/// The segments of the image whose first one is `first`, in order: the
/// file itself when its name does not end in `.001` (or `.000`), else it
/// and the files with the next numbers, as long as they are there.
pub fn segments_of(first: &Path) -> Vec<PathBuf> {
    let mut out = vec![first.to_path_buf()];
    let Some(name) = first.file_name().and_then(|n| n.to_str()) else { return out };
    let Some((stem, ext)) = name.rsplit_once('.') else { return out };
    if ext.len() < 3 || !ext.bytes().all(|b| b.is_ascii_digit()) {
        return out;
    }
    let Ok(start) = ext.parse::<u64>() else { return out };
    if start > 1 {
        return out; // a later segment given by itself: read as it is
    }
    let mut n = start + 1;
    loop {
        let next = first.with_file_name(format!("{}.{:0width$}", stem, n, width = ext.len()));
        if !next.is_file() {
            break;
        }
        out.push(next);
        n += 1;
    }
    out
}

impl RawImage {
    pub fn open(path: &str) -> io::Result<RawImage> {
        let mut parts = Vec::new();
        let mut at = 0u64;
        for p in segments_of(Path::new(path)) {
            let f = File::open(&p)?;
            let len = f.metadata()?.len();
            parts.push((f, at, len));
            at += len;
        }
        Ok(RawImage { parts, len: at, pos: 0 })
    }

    /// The size of the whole image.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// How many files the image is made of.
    pub fn segments(&self) -> usize {
        self.parts.len()
    }
}

impl Read for RawImage {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        // the segment the place is in
        let i = self.parts.partition_point(|(_, start, len)| start + len <= self.pos);
        let Some((f, start, len)) = self.parts.get_mut(i) else { return Ok(0) };
        let within = self.pos - *start;
        let want = (buf.len() as u64).min(*len - within) as usize;
        f.seek(SeekFrom::Start(within))?;
        let n = f.read(&mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for RawImage {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let to = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
        };
        self.pos = to.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start of the image"))?;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_split_image_reads_as_the_whole_one() {
        let dir = std::env::temp_dir().join(format!("masstin_split_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let whole: Vec<u8> = (0..10_000u32).flat_map(|i| i.to_le_bytes()).collect();
        // three segments of 16,384 bytes and what is left
        for (k, piece) in whole.chunks(16_384).enumerate() {
            File::create(dir.join(format!("disk.{:03}", k + 1))).unwrap().write_all(piece).unwrap();
        }
        let first = dir.join("disk.001");
        assert_eq!(segments_of(&first).len(), 3);
        let mut img = RawImage::open(first.to_str().unwrap()).unwrap();
        assert_eq!((img.len(), img.segments()), (40_000, 3));
        let mut all = Vec::new();
        img.read_to_end(&mut all).unwrap();
        assert_eq!(all, whole);
        // a read across the end of a segment, after a seek
        img.seek(SeekFrom::Start(16_380)).unwrap();
        let mut b = [0u8; 12];
        img.read_exact(&mut b).unwrap();
        assert_eq!(&b[..], &whole[16_380..16_392]);
        assert_eq!(img.seek(SeekFrom::End(-4)).unwrap(), 39_996);
        // a file that is no first segment is itself alone
        assert_eq!(segments_of(&dir.join("disk.002")).len(), 1);
        File::create(dir.join("plain.dd")).unwrap().write_all(&whole[..100]).unwrap();
        assert_eq!(segments_of(&dir.join("plain.dd")).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
