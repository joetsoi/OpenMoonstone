use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::io;
use std::io::prelude::*;
use std::io::Write;

use bv::BitSlice;
use byteorder::{BigEndian, ByteOrder};

use crate::lz77;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Colour {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

#[derive(Debug, Clone)]
pub struct PivImage {
    pub palette: Vec<Colour>,
    pub raw_palette: Vec<u16>,
    pixels: Vec<usize>,
}

impl fmt::Display for PivImage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PivImage {} pixels", self.pixels.len())
    }
}

impl PivImage {
    pub fn from_reader<T: Read>(reader: &mut T) -> Result<PivImage, io::Error> {
        let mut data: Vec<u8> = Vec::new();
        reader.read_to_end(&mut data)?;
        let header = PivImage::read_header(&data[..6]);

        let raw_palette = read_palette(header.bit_depth, &data[6..6 + (header.bit_depth * 2)]);
        let palette: Vec<Colour> = extract_palette(&raw_palette);

        let extracted = lz77::decompress(
            u32::from(header.file_length),
            &data[6 + (header.bit_depth * 2)..],
        )?;
        let pixels = PivImage::combine_bit_planes(&extracted);
        Ok(PivImage {
            palette,
            raw_palette,
            pixels,
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

    pub fn to_rgba8_512(&self) -> Vec<u8> {
        let width = 320;
        let height = 200;

        let mut pixels: Vec<u8> = Vec::with_capacity(512 * 512 * 4);
        for y in 0..512 {
            for x in 0..512 {
                if x < width && y < height {
                    let pel = self.pixels[y * width + x];
                    let colour = &self.palette[pel];
                    pixels.extend([colour.r, colour.g, colour.b, colour.a].iter())
                } else {
                    pixels.extend([0, 0, 0, 0].iter())
                }
            }
        }
        pixels
    }

    pub fn swap_colours(mut self, swaps: &HashMap<usize, u16>) -> Self {
        // let mut base_palette = self.raw_palette.to_vec();
        for (i, new_colour) in swaps {
            if let Some(c) = self.raw_palette.get_mut(*i) {
                *c = *new_colour;
            } else {
                writeln!(
                    io::stderr(),
                    "Tried swapping the {}th colour when the palette only has {} colours",
                    self.palette.len(),
                    i
                );
            }
        }
        self
    }

    pub fn build_palette(mut self) -> Self {
        self.palette.splice(.., extract_palette(&self.raw_palette));
        self
    }

    fn read_header(data: &[u8]) -> Header {
        let file_type = BigEndian::read_u16(&data[..2]);
        Header {
            file_length: BigEndian::read_u16(&data[4..6]),
            bit_depth: 1usize.wrapping_shl(u32::from(file_type)),
        }
    }

    fn combine_bit_planes(data: &[u8]) -> Vec<usize> {
        let planes: Vec<BitSlice<u8>> =
            data.chunks(8000).map(|p| BitSlice::from_slice(p)).collect();

        let mut pixels: Vec<usize> = Vec::with_capacity(64000);
        for i in (0..64000).map(|x| 7 - (x % 8) + x / 8 * 8) {
            let mut sum = 0;
            for (j, plane) in planes.iter().enumerate() {
                sum += (plane[i] as usize) << j;
            }

            pixels.push(sum);
        }
        pixels
    }
}

#[derive(Debug, Copy, Clone)]
struct Header {
    file_length: u16,
    bit_depth: usize,
}

fn read_palette(bit_depth: usize, data: &[u8]) -> Vec<u16> {
    let mut palette = vec![0; bit_depth];
    BigEndian::read_u16_into(&data, &mut palette);
    let palette: Vec<u16> = palette.iter().map(|pel| pel & 0x7fff).collect();
    palette
}

pub fn extract_palette(data: &[u16]) -> Vec<Colour> {
    let mut palette: Vec<Colour> = data
        .iter()
        .map(|pel| {
            let mut pel_bytes = [0u8; 2];
            BigEndian::write_u16(&mut pel_bytes, *pel);
            Colour {
                r: (pel_bytes[0]) << 4,
                g: ((pel_bytes[1]) & 0xf0), // >> 2) << 2,
                b: ((pel_bytes[1]) & 0x0f) << 4,
                a: 255,
            }
        })
        .collect();
    if let Some(first) = palette.get_mut(0) {
        first.a = 0;
    }
    palette
}

pub fn palette_swap(base_palette: &[u16], swap: &[u16]) -> Vec<Colour> {
    let mut base_palette = base_palette.to_vec();
    let _: Vec<u16> = base_palette.splice(6..9, swap.to_vec()).collect();
    extract_palette(&base_palette)
}

pub struct ColourOscillate {
    from: Colour,
    to: Colour,
    current: Colour,
    target: Colour,
}

impl ColourOscillate {
    pub fn new(from: Colour, to: Colour) -> Self {
        ColourOscillate {
            from: from.clone(),
            to: to.clone(),
            current: from.clone(),
            target: to.clone(),
        }
    }
}

impl Iterator for ColourOscillate {
    type Item = Colour;

    fn next(&mut self) -> Option<Self::Item> {
        if self.target.r > self.current.r {
            self.current.r += 16
        } else if self.target.r < self.current.r {
            self.current.r -= 16
        };

        if self.target.g > self.current.g {
            self.current.g += 16
        } else if self.target.g < self.current.g {
            self.current.g -= 16
        };

        if self.target.b > self.current.b {
            self.current.b += 16
        } else if self.target.b < self.current.b {
            self.current.b -= 16
        };

        if self.current == self.target {
            if self.target == self.from {
                self.target = self.to
            } else {
                self.target = self.from
            }
        }
        Some(self.current.clone())
    }
}
