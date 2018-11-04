use std::collections::HashMap;
use std::io;
use std::io::Read;

use failure::err_msg;
use failure::format_err;
use failure::Error;
use pest::Parser;
use pest_derive::*;

pub struct CollisionBoxes {
    pub data: HashMap<String, Vec<Option<Vec<(u32, u32)>>>>,
}

#[derive(Parser)]
#[grammar = "files/collision.pest"]
pub struct CollisionParser;

pub fn parse_collide_hit<T: Read>(reader: &mut T) -> Result<CollisionBoxes, Error> {
    let mut buffer = String::new();
    reader.read_to_string(&mut buffer)?;
    let successful_parse = CollisionParser::parse(Rule::named_collisions, &buffer);

    let mut data = HashMap::new();
    for i in successful_parse? {
        let mut inner = i.into_inner();
        let filename = inner
            .next()
            .ok_or_else(|| err_msg("No filename parsing collide.hit"))?
            .as_str();
        let collisions = inner
            .next()
            .ok_or_else(|| err_msg("no collisions parsing collide.hit"))?;

        let mut collision_boxes: Vec<Option<Vec<(u32, u32)>>> = Vec::new();
        for collision_entry in collisions.into_inner() {
            match collision_entry.as_rule() {
                Rule::empty => collision_boxes.push(None),
                Rule::bounding_boxes => {
                    let mut inner_bounding_boxes = collision_entry.into_inner();
                    let count = inner_bounding_boxes
                        .next()
                        .ok_or_else(|| err_msg("No count for bounding boxes"))?
                        .as_str();

                    let mut boxes: Vec<(u32, u32)> = Vec::new();
                    for coordinates in inner_bounding_boxes {
                        let mut inner_rules = coordinates.into_inner();
                        let x: u32 = inner_rules
                            .next()
                            .ok_or_else(|| err_msg("Couldn't parse x coord"))?
                            .as_str()
                            .parse::<u32>()?;
                        let y: u32 = inner_rules
                            .next()
                            .ok_or_else(|| err_msg("Couldn't parse y coord"))?
                            .as_str()
                            .parse::<u32>()?;
                        boxes.push((x, y));
                    }
                    collision_boxes.push(Some(boxes));
                }
                _ => (),
            }
        }
        data.insert(filename.to_string(), collision_boxes);
    }
    Ok(CollisionBoxes { data: data })
}
