use specs::VecStorage;
use specs_derive::*;

use crate::rect::Rect;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Body {
    pub collision_boxes: Option<Vec<Rect>>,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Weapon {
    pub collision_boxes: Option<Vec<Rect>>,
}
