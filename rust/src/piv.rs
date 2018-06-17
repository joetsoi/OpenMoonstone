use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

use lz77;

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
            pixels: lz77::decompress(header.file_length, &data[6 + (header.bit_depth * 2)..])?,
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
