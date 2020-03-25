use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Endurance {
    pub max: u32,
    pub used: u32,
    pub spent: u32,
}
