use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

use bv::BitSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

use crate::lz77;
use crate::piv::Colour;

#[derive(Debug)]
struct Header {
    image_count: usize,
    file_length: u16,
}

#[derive(Debug)]
pub struct ObjectsFile {
    pub images: Vec<Image>,
}

#[derive(Debug, Copy, Clone)]
struct ImageHeader {
    data_address: usize,
    width: usize,
    height: usize,
    bit_plane_count: usize,
    blit_type: u8,
}

impl ObjectsFile {
    pub fn from_file(filename: &String) -> Result<ObjectsFile, io::Error> {
        let mut f = File::open(filename)?;
        let mut data: Vec<u8> = Vec::new();
        f.read_to_end(&mut data)?;

        let header = ObjectsFile::read_header(&data[..6]);
        let image_header_len = header.image_count * 10;
        let image_headers =
            ObjectsFile::read_image_headers(&header, &data[10..image_header_len + 10])?;

        let extracted = lz77::decompress(header.file_length, &data[image_header_len + 10..])?;
        let mut images: Vec<Image> = Vec::new();
        for image_header in image_headers {
            images.push(Image::from_data(image_header, &extracted));
        }
        Ok(ObjectsFile { images: images })
    }

    fn read_header(data: &[u8]) -> Header {
        Header {
            image_count: BigEndian::read_u16(&data[..2]) as usize,
            file_length: BigEndian::read_u16(&data[4..6]),
        }
    }

    fn read_image_headers(header: &Header, data: &[u8]) -> Result<Vec<ImageHeader>, io::Error> {
        let mut rdr = Cursor::new(data);
        let mut headers: Vec<ImageHeader> = Vec::with_capacity(header.image_count);
        for _ in 0..header.image_count {
            rdr.seek(SeekFrom::Current(2))?;
            headers.push(ImageHeader {
                data_address: rdr.read_u16::<BigEndian>()? as usize,
                width: rdr.read_u16::<BigEndian>()? as usize,
                height: rdr.read_u16::<BigEndian>()? as usize,
                bit_plane_count: rdr.read_u8()? as usize,
                blit_type: rdr.read_u8()?,
            })
        }
        Ok(headers)
    }
}

#[derive(Debug)]
pub struct Image {
    pub width: usize,
    pub height: usize,
    pixels: Vec<usize>,
}

impl Image {
    fn from_data(header: ImageHeader, extracted: &[u8]) -> Image {
        let packed_image_width = (header.width + 15) / 16 * 2;
        let mut num_bit_planes = (8 - header.blit_type.leading_zeros()) as usize;
        if header.blit_type == 32 {
            num_bit_planes = 2;
        }
        let bit_plane_size = packed_image_width * header.height;
        let unpacked_image_width = packed_image_width * 8;

        let image_data =
            &extracted[header.data_address..header.data_address + bit_plane_size * num_bit_planes];
        let planes: Vec<BitSlice<u8>> = image_data
            .chunks(bit_plane_size)
            .map(|p| BitSlice::from_slice(p))
            .collect();

        let mut pixels: Vec<usize> = Vec::with_capacity(unpacked_image_width * header.height);
        for i in (0..bit_plane_size * 8).map(|x| 7 - (x % 8) + x / 8 * 8) {
            let mut sum = 0;
            for (j, plane) in planes.iter().enumerate() {
                sum += (plane[i as u64] as usize) << j;
            }
            pixels.push(sum);
        }

        Image {
            width: unpacked_image_width,
            height: header.height,
            pixels: pixels,
        }
    }

    pub fn to_rgba8(&self, palette: &[Colour]) -> Vec<u8> {
        let mut pixels: Vec<u8> = Vec::with_capacity(self.width * self.height * 4);
        for pel in self.pixels.iter() {
            let colour = palette[*pel];
            pixels.extend([colour.r, colour.g, colour.b, colour.a].iter())
        }
        pixels
    }
}
