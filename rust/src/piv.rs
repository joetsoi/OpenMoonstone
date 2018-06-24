use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

use bv::BitSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

use lz77;

#[derive(Debug)]
pub struct Colour {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

#[derive(Debug)]
pub struct PivImage {
    palette: Vec<Colour>,
    pixels: Vec<usize>,
}

impl PivImage {
    pub fn from_file(filename: &String) -> Result<PivImage, io::Error> {
        let mut f = File::open(filename)?;
        let mut data: Vec<u8> = Vec::new();
        f.read_to_end(&mut data)?;
        let header = PivImage::read_header(&data[..6])?;

        let palette: Vec<Colour> =
            read_palette(header.bit_depth, &data[6..6 + (header.bit_depth * 2)])?;

        let extracted = lz77::decompress(header.file_length, &data[6 + (header.bit_depth * 2)..])?;
        let pixels = PivImage::combine_bit_planes(&extracted);
        Ok(PivImage {
            palette: palette,
            pixels: pixels,
        })
    }

    pub fn to_rgba8(&self) -> Vec<u8> {
        let width = 320;
        let height = 240;

        let mut pixels: Vec<u8> = Vec::with_capacity(width * height * 4);
        for pel in self.pixels.iter() {
            let colour = &self.palette[*pel];
            pixels.extend([colour.r, colour.g, colour.b, colour.a].iter())
        }
        pixels
    }

    fn read_header(data: &[u8]) -> Result<Header, io::Error> {
        let mut rdr = Cursor::new(data);
        let file_type = rdr.read_u16::<BigEndian>()?;
        rdr.seek(SeekFrom::Current(2))?;
        Ok(Header {
            file_length: rdr.read_u16::<BigEndian>()?,
            bit_depth: 1usize.wrapping_shl(file_type as u32),
        })
    }

    fn combine_bit_planes(data: &[u8]) -> Vec<usize> {
        let plane0 = BitSlice::from_slice(&data[..8000]);
        let plane1 = BitSlice::from_slice(&data[8000..16000]);
        let plane2 = BitSlice::from_slice(&data[16000..24000]);
        let plane3 = BitSlice::from_slice(&data[24000..32000]);
        let plane4 = BitSlice::from_slice(&data[32000..]);

        let mut pixels: Vec<usize> = Vec::with_capacity(64000);
        for i in (0..plane0.len()).map(|x| 7 - (x % 8) + x / 8 * 8) {
            let mut sum = 0;
            sum += plane0[i] as usize;
            sum += (plane1[i] as usize) << 1;
            sum += (plane2[i] as usize) << 2;
            sum += (plane3[i] as usize) << 3;
            sum += (plane4[i] as usize) << 4;

            pixels.push(sum);
        }
        pixels
    }
}

#[derive(Debug)]
struct Header {
    file_length: u16,
    bit_depth: usize,
}

pub fn read_palette(bit_depth: usize, data: &[u8]) -> Result<Vec<Colour>, io::Error> {
    let mut rdr = Cursor::new(data);
    let mut palette = vec![0; bit_depth];
    rdr.read_u16_into::<BigEndian>(&mut palette)?;
    let palette: Vec<u16> = palette.iter().map(|pel| pel & 0x7fff).collect();

    Ok(palette
        .iter()
        .map(|pel| {
            let mut pel_bytes = [0u8; 2];
            BigEndian::write_u16(&mut pel_bytes, *pel);
            let mut alpha = 0u8;
            if *pel != 0u16 {
                alpha = 255;
            }
            Colour {
                r: (pel_bytes[0]) << 4,
                g: (((pel_bytes[1]) & 0xf0) >> 2) << 2,
                b: ((pel_bytes[1]) & 0x0f) << 4,
                a: alpha,
            }
        })
        .collect())
}
