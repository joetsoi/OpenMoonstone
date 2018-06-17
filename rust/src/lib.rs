extern crate bv;
extern crate byteorder;

use bv::BitSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

#[derive(Debug)]
pub struct Colour {
    r: usize,
    g: usize,
    b: usize,
}

#[derive(Debug)]
pub struct PivImage {
    palette: Vec<Colour>,
    pixels: Vec<u8>,
}

impl PivImage {
    pub fn from_file(filename: &String) -> Result<(PivImage), Box<Error>> {
        let mut f = File::open(filename)?;
        let mut data: Vec<u8> = Vec::new();
        f.read_to_end(&mut data)?;
        let header = PivImage::read_header(&data[..6])?;

        let palette: Vec<Colour> =
            read_palette(header.bit_depth, &data[6..6 + (header.bit_depth * 2)])?;

        Ok(PivImage {
            palette: palette,
            pixels: decompress(header.file_length, &data[6 + (header.bit_depth * 2)..])?;
        })
    }

    fn read_header(data: &[u8]) -> Result<Header, Box<Error>> {
        let mut rdr = Cursor::new(data);
        let file_type = rdr.read_u16::<BigEndian>()?;
        rdr.seek(SeekFrom::Current(2))?;
        Ok(Header {
            file_length: rdr.read_u16::<BigEndian>()?,
            bit_depth: 1usize.wrapping_shl(file_type as u32),
        })
    }
}

#[derive(Debug)]
struct Header {
    file_length: u16,
    bit_depth: usize,
}

pub fn read_palette(bit_depth: usize, data: &[u8]) -> Result<Vec<Colour>, Box<Error>> {
    let mut rdr = Cursor::new(data);
    let mut palette = vec![0; bit_depth];
    rdr.read_u16_into::<BigEndian>(&mut palette)?;
    let palette: Vec<u16> = palette.iter().map(|pel| pel & 0x7fff).collect();

    Ok(palette
        .iter()
        .map(|pel| {
            let mut pel_bytes = [0u8; 2];
            BigEndian::write_u16(&mut pel_bytes, *pel);
            Colour {
                r: (pel_bytes[0] as usize) << 4,
                g: (((pel_bytes[1] as usize) & 0xf0) >> 2) << 2,
                b: ((pel_bytes[1] as usize) & 0x0f) << 4,
            }
        })
        .collect())
}

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
