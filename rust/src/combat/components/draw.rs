use specs::{Component, VecStorage};
//use specs_derive::*;
use super::Facing;
use crate::animation::Frame;

#[derive(Debug)]
pub struct Draw {
    pub frame: Frame,
    pub animation: String,
    pub direction: Facing,
}

impl Component for Draw {
    type Storage = VecStorage<Self>;
}
