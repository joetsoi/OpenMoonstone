use specs::VecStorage;
use specs_derive::*;

use super::Facing;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Position {
    pub x: i32,
    pub y: i32,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Velocity {
    pub x: i32,
    pub y: i32,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct WalkingState {
    pub direction: Facing,
    pub step: u32,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Controller {
    pub x: i32,
    pub y: i32,
    pub fire: bool,
}
