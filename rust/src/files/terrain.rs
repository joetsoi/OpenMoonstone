use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use lazy_static::lazy_static;
use maplit::hashmap;

use crate::lz77;
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
pub struct Header {
    pub y: u32,
}

#[derive(Debug)]
pub struct TerrainFile {
    pub headers: Vec<Header>,
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
    fn read_headers(header_count: usize, data: &[u8]) -> Result<Vec<Header>, io::Error> {
        let mut headers: Vec<Header> = Vec::new();
        for _ in 0..header_count {
            let _a = BigEndian::read_u16(&data[0..2]) as i32;
            let _b = BigEndian::read_u16(&data[2..4]) as i32;
            let y = BigEndian::read_u16(&data[4..6]) as u32;
            let _c = BigEndian::read_u16(&data[6..8]) as u32;
            headers.push(Header { y });
        }
        Ok(headers)
        //Ok(Header {
        //    //x: left,
        //    y,
        //    // w: (right - left) as u32,
        //    // h: bottom - 30,
        //})
    }

    fn read_terrain_positions(data: &[u8]) -> Result<Vec<Position>, io::Error> {
        let mut rdr = Cursor::new(data);
        let mut positions: Vec<Position> = Vec::new();

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

        let file_length = BigEndian::read_u32(&data[..4]);
        let extracted = lz77::decompress(file_length, &data[4..])?;
        let header_count = BigEndian::read_u16(&extracted[..2]) as usize;
        let positions_start = (8 * header_count) + 2;

        let headers = TerrainFile::read_headers(header_count, &extracted[2..positions_start])?;
        let positions = TerrainFile::read_terrain_positions(&extracted[positions_start..])?;
        Ok(TerrainFile { headers, positions })
    }
}
