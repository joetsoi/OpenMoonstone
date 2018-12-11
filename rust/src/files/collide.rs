use std::collections::HashMap;
use std::io::Read;

use failure::err_msg;
use failure::Error;
use pest::Parser;
use pest_derive::*;

#[derive(Default, Copy, Clone, Debug)]
pub struct Point {
    pub x: u32,
    pub y: u32,
}

#[derive(Default, Clone, Debug)]
pub struct Points {
    pub data: Vec<Point>,
    pub max_x: u32,
    pub max_y: u32,
}

#[derive(Default, Clone, Debug)]
pub struct CollisionPoints {
    pub points: Vec<Option<Points>>,
}

#[derive(Default, Clone, Debug)]
pub struct CollisionBoxes {
    pub data: HashMap<String, CollisionPoints>,
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

        let mut collision_boxes: Vec<Option<Points>> = Vec::new();
        for collision_entry in collisions.into_inner() {
            match collision_entry.as_rule() {
                Rule::empty => collision_boxes.push(None),
                Rule::bounding_boxes => {
                    let mut inner_bounding_boxes = collision_entry.into_inner();
                    let _count = inner_bounding_boxes
                        .next()
                        .ok_or_else(|| err_msg("No count for bounding boxes"))?
                        .as_str();

                    let mut points: Vec<Point> = Vec::new();
                    let mut max_x: u32 = 0;
                    let mut max_y: u32 = 0;
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

                        points.push(Point { x, y });
                        if x > max_x {
                            max_x = x;
                        }
                        if y > max_y {
                            max_y = y;
                        }
                    }
                    collision_boxes.push(Some(Points {
                        data: points,
                        max_x,
                        max_y,
                    }));
                }
                _ => (),
            }
        }
        data.insert(
            filename.to_string(),
            CollisionPoints {
                points: collision_boxes,
            },
        );
    }
    Ok(CollisionBoxes { data })
}
