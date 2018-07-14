use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Position {
    pub x: u32,
    pub y: u32,
}
