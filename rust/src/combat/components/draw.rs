use super::Facing;
use crate::animation::Frame;
use crate::piv::Colour;
use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Component, Default, Debug, Clone)]
#[storage(VecStorage)]
pub struct Draw {
    pub frame: Frame,
    pub animation: String,
    pub direction: Facing,
}

/// Used for assigning a different palette to a knight
#[derive(Component, Debug, Clone, Default)]
#[storage(VecStorage)]
pub struct Palette {
    pub name: String,
    pub palette: Vec<Colour>,
}
