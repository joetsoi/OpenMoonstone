use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Controller, Direction, Position, WalkingState};

pub const X_STEP_SIZES: [[i32; 4]; 3] = [[25, 3, 23, 4], [0, 0, 0, 0], [25, 3, 23, 4]];
pub const Y_STEP_SIZES: [[i32; 4]; 3] = [[2, 9, 2, 9], [0, 0, 0, 0], [8, 2, 9, 2]];

pub struct Movement;

impl<'a> System<'a> for Movement {
    type SystemData = (
        ReadStorage<'a, Controller>,
        WriteStorage<'a, Position>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(&mut self, (controller, mut position, mut walking_state): Self::SystemData) {
        use specs::Join;

        for (controller, position, walking_state) in
            (&controller, &mut position, &mut walking_state).join()
        {
            let is_moving = (controller.x | controller.y) & 1;
            let step = ((walking_state.step + 1) % 4) * is_moving as u32;

            let x_delta = X_STEP_SIZES[(controller.x + 1) as usize][step as usize] * controller.x;
            let y_delta = Y_STEP_SIZES[(controller.y + 1) as usize][step as usize] * controller.y;

            position.x = (position.x as i32 + x_delta) as u32;
            position.y = (position.y as i32 - y_delta) as u32;
            walking_state.step = step;
            match controller.x {
                1 => walking_state.direction = Direction::Right,
                -1 => walking_state.direction = Direction::Left,
                _ => (),
            }
        }
    }
}
