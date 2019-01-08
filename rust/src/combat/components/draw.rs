use super::Facing;
use crate::animation::Frame;
use crate::piv::Colour;
use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Draw {
    pub frame: Frame,
    pub animation: String,
    pub resource_name: String,
    pub direction: Facing,
}

/// Used for assigning a different palette to a knight
#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Palette {
    pub name: String,
    pub palette: Vec<Colour>,
}
