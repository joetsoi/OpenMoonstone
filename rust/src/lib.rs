extern crate byteorder;
extern crate bv;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;
use bv::BitSlice;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};


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


pub fn decompress(filename: &String) -> Result<(PivImage), Box<Error>> {
    // header
    let mut f = File::open(filename)?;
    let mut data: Vec<u8> = Vec::new();
    f.read_to_end(&mut data)?;
    let mut rdr = Cursor::new(data);
    let file_type = rdr.read_u16::<BigEndian>()?;
    rdr.seek(SeekFrom::Current(2))?;
    let file_length = rdr.read_u16::<BigEndian>()?;
    let bit_depth = 1u32.wrapping_shl(file_type as u32);
    // palette
    let mut palette = vec![0; bit_depth as usize];
    rdr.read_u16_into::<BigEndian>(&mut palette)?;

    let palette: Vec<u16> = palette.iter().map(|pel| pel & 0x7fff).collect();
    let palette: Vec<Colour> = palette.iter().map(|pel| {
        let mut pel_bytes = [0u8; 2];
        BigEndian::write_u16(&mut pel_bytes, *pel);
        Colour {
            r: (pel_bytes[0] as usize) << 4,
            g: (((pel_bytes[1] as usize) & 0xf0) >> 2) << 2,
            b: ((pel_bytes[1] as usize) & 0x0f) << 4,
        }
    }).collect();
    println!("{:?}, {:?}, {:?}", file_length, bit_depth, palette);

    let mut extracted: Vec<u8> = Vec::with_capacity(file_length as usize);
    //let mut offset = 0;
    let file_start = rdr.position();
    while rdr.position() - file_start != file_length as u64 {
    //while offset != file_length as usize {
        let header = [rdr.read_u8()?];
        //offset += 1;

        let slice = BitSlice::from_slice(&header);
        for i in (0..slice.len()).rev() {
            let is_run = slice[i];
            //println!("{:?}", slice[i]);
            if is_run {
                let encoded = rdr.read_u16::<BigEndian>()?;
                //offset += 2;
                let count = (0x22 - ((encoded & 0xf800) >> 11)) as usize;
                //println!("count : {:?}", _count);
                let copy_source = encoded & 0x7ff;
                //println!("copy source: {:?}, extracted len: {:?}", copy_source, extracted.len());
                let copy_from = extracted.len() - copy_source as usize;
                let mut existing_bytes = vec![0u8; extracted[copy_from..].len()];
                existing_bytes.clone_from_slice(&extracted[copy_from..]);
                let new_bytes = existing_bytes.iter().cycle().take(count);

                extracted.extend(new_bytes);
            } else {
                let encoded = rdr.read_u8()?;
                //offset += 1;
                extracted.push(encoded);
            }
            //println!("pos {:?} {:?}", rdr.position() - file_start, file_length);
            if rdr.position() - file_start >= file_length as u64 {
            //if offset >= file_length as u64 {
                break;
            }
        }
        //println!("{:?} {:?}", file_length, offset);
    }
    //println!("{:?}", extracted);
    
    Ok(PivImage {
        palette: palette,
        pixels: extracted,
    })
}
