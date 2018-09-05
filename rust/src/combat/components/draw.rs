use super::Facing;
use crate::animation::Frame;
use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Draw {
    pub frame: Frame,
    pub animation: String,
    pub direction: Facing,
}
