use specs::VecStorage;
use specs_derive::*;

use crate::rect::{Point, Rect};

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Body {
    pub collision_boxes: Option<Vec<Rect>>,
}

#[derive(Clone, Debug)]
pub struct Points {
    pub bounding: Rect,
    pub points: Vec<Point>,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Weapon {
    pub collision_points: Option<Vec<Points>>,
}
