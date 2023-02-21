use specs::{Component, VecStorage};
use specs_derive::*;

use super::Facing;
use crate::combat::resources::StepDistance;
use crate::input;
use crate::rect::Point;

#[derive(Component, Debug, Default, Clone)]
#[storage(VecStorage)]
pub struct Position {
    pub x: i32,
    pub y: i32,
}

pub fn get_distance(a: &Position, b: &Position) -> Point {
    Point {
        x: a.x - b.x,
        y: a.y - b.y,
    }
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Velocity {
    pub x: i32,
    pub y: i32,
}

#[derive(Component, Clone, Debug, Default)]
#[storage(VecStorage)]
pub struct WalkingState {
    pub direction: Facing,
    pub step: u32,
    pub step_distances: StepDistance,
}

#[derive(Component, Clone, Debug)]
#[storage(VecStorage)]
pub struct Controller {
    pub x: i32,
    pub y: i32,
    pub fire: bool,

    pub x_axis: input::Axis,
    pub y_axis: input::Axis,
    pub button: input::Button,
}

impl Default for Controller {
    fn default() -> Self {
        Controller {
            x: 0,
            y: 0,
            fire: false,
            x_axis: input::Axis::Horz1,
            y_axis: input::Axis::Vert1,
            button: input::Button::Fire1,
        }
    }
}
