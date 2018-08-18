use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Controller, Direction, Velocity, WalkingState};

pub const X_STEP_SIZES: [[i32; 4]; 3] = [[25, 3, 23, 4], [0, 0, 0, 0], [25, 3, 23, 4]];
pub const Y_STEP_SIZES: [[i32; 4]; 3] = [[8, 2, 9, 2], [0, 0, 0, 0], [2, 9, 2, 9]];
// check y step sizes

pub struct VelocitySystem;

impl<'a> System<'a> for VelocitySystem {
    type SystemData = (
        ReadStorage<'a, Controller>,
        WriteStorage<'a, Velocity>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(&mut self, (controller, mut velocity, mut walking_state): Self::SystemData) {
        use specs::Join;

        for (controller, velocity, walking_state) in
            (&controller, &mut velocity, &mut walking_state).join()
        {
            let is_moving = (controller.x | controller.y) & 1;
            let step = ((walking_state.step + 1) % 4) * is_moving as u32;

            velocity.x = X_STEP_SIZES[(controller.x + 1) as usize][step as usize] * controller.x;
            velocity.y = Y_STEP_SIZES[(controller.y + 1) as usize][step as usize] * controller.y;

            walking_state.step = step;
            match controller.x {
                1 => walking_state.direction = Direction::Right,
                -1 => walking_state.direction = Direction::Left,
                _ => (),
            }
        }
    }
}
