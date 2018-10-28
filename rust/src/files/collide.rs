use std::collections::HashMap;
use std::io;
use std::io::Read;

use pest::Parser;
use pest_derive::*;

pub struct CollisionBoxes {
    pub data: HashMap<String, Vec<(u32, u32)>>,
}

#[derive(Parser)]
#[grammar = "files/collision.pest"]
pub struct CollisionParser;

pub fn parse_collide_hit<T: Read>(reader: &mut T) -> Result<CollisionBoxes, io::Error> {
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer)?;
    let successful_parse = CollisionParser::parse(Rule::named_collisions, &buffer);
    for i in successful_parse.unwrap() {
        let mut inner = i.into_inner();
        let filename = inner.next().unwrap().as_str();
        let collisions = inner.next().unwrap();
        println!("{:#?}", filename);
        for collision_entry in collisions.into_inner() {
            match collision_entry.as_rule() {
                Rule::empty => {
                    println!("empty");
                }
                Rule::bounding_boxes => {
                    let mut inner_bounding_boxes = collision_entry.into_inner();
                    let count = inner_bounding_boxes.next().unwrap().as_str();

                    //println!("{:#?}", inner_bounding_boxes);
                    for coordinates in inner_bounding_boxes {
                        let mut inner_rules = coordinates.into_inner();
                        let x: u32 = inner_rules.next().unwrap().as_str().parse::<u32>().unwrap();
                        let y: u32 = inner_rules.next().unwrap().as_str().parse::<u32>().unwrap();

                        println!("x: {:#?}, y: {:#?}", x, y);
                    }
                }
                _ => (),
            }
        }
    }
    Ok(CollisionBoxes {
        data: HashMap::new(),
    })
}
