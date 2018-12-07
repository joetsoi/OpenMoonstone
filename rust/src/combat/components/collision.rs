use specs::VecStorage;
use specs_derive::*;

use crate::rect::Rect;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Collision {
    pub bounding_boxes: Vec<Rect>,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct AttackCollider {
    pub bounding_boxes: Vec<Rect>,
}
