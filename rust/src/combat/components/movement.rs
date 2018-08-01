use specs::VecStorage;
use specs_derive::*;

#[derive(Debug)]
pub enum Direction {
    Left = -1,
    Right= 1,
}

impl Default for Direction {
    fn default() -> Direction {
        Direction::Right
    }
}

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Position {
    pub x: u32,
    pub y: u32,
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct WalkingState {
    pub direction: Direction,
    pub step: u32,
}

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Controller {
    pub x: i32,
    pub y: i32,
    pub fire: bool,
}
