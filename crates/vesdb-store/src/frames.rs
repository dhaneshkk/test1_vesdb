//! Framed append-only files: `[u32 len BE][u32 crc32c(body) BE][body]`.
//!
//! Recovery reads frames until the first short or bad frame. A bad frame that is the last thing
//! in the file is a torn write (never acknowledged) and is truncated away; anything after a bad
//! frame means the file was damaged and the store refuses to open.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;

pub const HEADER: u64 = 8;

#[derive(Debug)]
pub struct Frame {
    pub offset: u64,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct Scan {
    pub frames: Vec<Frame>,
    /// Length of the valid prefix.
    pub good_len: u64,
    /// Bytes after the valid prefix (torn tail or damage).
    pub trailing: u64,
    /// A bad frame was followed by more data: damage, not a torn write.
    pub damaged: bool,
}

pub fn encode(body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(body.len() + HEADER as usize);
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(&crc32c::crc32c(body).to_be_bytes());
    f.extend_from_slice(body);
    f
}

pub fn scan(file: &mut File) -> io::Result<Scan> {
    let total = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::with_capacity(total as usize);
    file.read_to_end(&mut buf)?;
    let mut frames = Vec::new();
    let mut pos = 0usize;
    let mut damaged = false;
    while pos < buf.len() {
        if buf.len() - pos < HEADER as usize {
            break;
        }
        let len = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        let crc = u32::from_be_bytes(buf[pos + 4..pos + 8].try_into().unwrap());
        let start = pos + HEADER as usize;
        if start + len > buf.len() {
            break; // torn tail
        }
        let body = &buf[start..start + len];
        if crc32c::crc32c(body) != crc {
            damaged = start + len < buf.len();
            break;
        }
        frames.push(Frame {
            offset: pos as u64,
            body: body.to_vec(),
        });
        pos = start + len;
    }
    Ok(Scan {
        frames,
        good_len: pos as u64,
        trailing: (buf.len() - pos) as u64,
        damaged,
    })
}

pub fn append(file: &mut File, body: &[u8]) -> io::Result<u64> {
    let off = file.seek(SeekFrom::End(0))?;
    file.write_all(&encode(body))?;
    Ok(off)
}

/// Overwrite the body of the frame at `offset` with `body` of the same length (redaction).
pub fn rewrite(file: &File, offset: u64, body: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 8];
    file.read_exact_at(&mut hdr, offset)?;
    let len = u32::from_be_bytes(hdr[..4].try_into().unwrap()) as usize;
    if len != body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rewrite must keep frame length",
        ));
    }
    file.write_all_at(&crc32c::crc32c(body).to_be_bytes(), offset + 4)?;
    file.write_all_at(body, offset + HEADER)
}

pub fn read_body(file: &File, offset: u64) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 8];
    file.read_exact_at(&mut hdr, offset)?;
    let len = u32::from_be_bytes(hdr[..4].try_into().unwrap()) as usize;
    let crc = u32::from_be_bytes(hdr[4..].try_into().unwrap());
    let mut body = vec![0u8; len];
    file.read_exact_at(&mut body, offset + HEADER)?;
    if crc32c::crc32c(&body) != crc {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame checksum mismatch",
        ));
    }
    Ok(body)
}
