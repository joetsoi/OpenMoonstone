use specs::{Entity, VecStorage};
use specs_derive::*;

use crate::rect::{Point, Rect};

#[derive(Clone, Debug, Default)]
pub struct CollisionBox {
    pub rect: Rect,
    pub sheet: String,
    pub image_num: u32,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Body {
    pub collision_boxes: Option<Vec<CollisionBox>>,
    pub rect: Option<Rect>,
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

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Collided {
    pub target: Entity,
}
