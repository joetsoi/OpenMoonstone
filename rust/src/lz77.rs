extern crate bv;
extern crate byteorder;

use bv::BitSlice;
use byteorder::{BigEndian, ReadBytesExt};
use std::error::Error;
use std::io::Cursor;

pub fn decompress(file_length: u16, data: &[u8]) -> Result<Vec<u8>, Box<Error>> {
    let mut rdr = Cursor::new(data);
    let mut extracted: Vec<u8> = Vec::with_capacity(file_length as usize);
    while rdr.position() != file_length as u64 {
        let header = [rdr.read_u8()?];
        let slice = BitSlice::from_slice(&header);

        for i in (0..slice.len()).rev() {
            let is_run = slice[i];
            if is_run {
                let encoded = rdr.read_u16::<BigEndian>()?;
                let count = (0x22 - ((encoded & 0xf800) >> 11)) as usize;
                let copy_source = encoded & 0x7ff;
                let copy_from = extracted.len() - copy_source as usize;
                let mut existing_bytes = vec![0u8; extracted[copy_from..].len()];
                existing_bytes.clone_from_slice(&extracted[copy_from..]);
                let new_bytes = existing_bytes.iter().cycle().take(count);

                extracted.extend(new_bytes);
            } else {
                let encoded = rdr.read_u8()?;
                extracted.push(encoded);
            }
            if rdr.position() >= file_length as u64 {
                break;
            }
        }
    }
    Ok(extracted)
}
