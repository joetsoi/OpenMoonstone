use specs::VecStorage;
use specs_derive::*;

use crate::rect::Rect;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Collision {
    pub bounding_boxes: Vec<Rect>,
    pub ticks: u32,
}
