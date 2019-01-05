use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use ggez::graphics::Image;
use lazy_static::lazy_static;
use maplit::hashmap;

use crate::lz77;
use crate::objects::TextureAtlas;
use crate::rect::Rect;

lazy_static! {
    static ref scenery_lookup: HashMap<u32, &'static str> = hashmap! {
        0 => "fo1",
        1 => "fo1",
        2 => "sw1",
        3 => "wa1",
        4 => "fo2",
    };
    pub static ref scenery_rects: Vec<Rect> = {
        let mut rects: Vec<Rect> = Vec::new();
        for y in 0..10 {
            for x in 0..10 {
                rects.push(Rect {
                    x: 32 * x,
                    y: 25 * y,
                    w: 32,
                    h: 25,
                })
            }
        }
        rects
    };
}

#[derive(Debug)]
struct Header {
    file_length: u32,
}

#[derive(Debug)]
pub struct TerrainFile {
    pub boundary: Rect,
    pub positions: Vec<Position>,
}

#[derive(Debug)]
pub struct Position {
    pub atlas: String,
    pub image_number: usize,
    pub x: u32,
    pub y: u32,
}

impl TerrainFile {
    fn read_header(data: &[u8]) -> Header {
        Header {
            file_length: BigEndian::read_u32(&data[..4]),
        }
    }

    fn read_boundary(data: &[u8]) -> Result<Rect, io::Error> {
        let left = BigEndian::read_u16(&data[0..2]) as i32;
        let right = BigEndian::read_u16(&data[2..4]) as i32;
        let bottom = BigEndian::read_u16(&data[4..6]) as u32;
        let _top = BigEndian::read_u16(&data[6..8]) as u32;
        Ok(Rect {
            x: left,
            y: 30,
            w: (right - left) as u32,
            h: bottom - 30,
        })
    }

    fn read_terrain_positions(count: usize, data: &[u8]) -> Result<Vec<Position>, io::Error> {
        let mut rdr = Cursor::new(data);
        let mut positions: Vec<Position> = Vec::with_capacity(count);

        loop {
            let atlas = rdr.read_u8()? as u32;
            let image_number = rdr.read_u8()? as usize;

            let position = Position {
                atlas: scenery_lookup.get(&atlas).unwrap_or(&"fo2").to_string(),
                image_number,
                x: rdr.read_u16::<BigEndian>()? as u32,
                y: rdr.read_u16::<BigEndian>()? as u32,
            };
            if atlas == 0xff {
                break;
            }
            positions.push(position);
        }
        Ok(positions)
    }
}

impl TerrainFile {
    pub fn from_reader<T: Read>(reader: &mut T) -> Result<TerrainFile, io::Error> {
        let mut data: Vec<u8> = Vec::new();
        reader.read_to_end(&mut data)?;

        let header = TerrainFile::read_header(&data[..4]);
        let extracted = lz77::decompress(header.file_length, &data[4..])?;
        let image_count = BigEndian::read_u16(&extracted[..2]) as usize * 8;
        let boundary = TerrainFile::read_boundary(&extracted[2..])?;
        let positions = TerrainFile::read_terrain_positions(image_count, &extracted[10..])?;
        Ok(TerrainFile {
            boundary,
            positions,
        })
    }
}
