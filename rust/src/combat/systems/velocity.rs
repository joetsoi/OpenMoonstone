use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{XAxis, YAxis};
use crate::combat::components::{
    Command, Facing, Intent, TouchingBoundary, Velocity, WalkingState,
};

pub const X_STEP_SIZES: [[i32; 4]; 3] = [[-25, -3, -23, -4], [0, 0, 0, 0], [25, 3, 23, 4]];
pub const Y_STEP_SIZES: [[i32; 4]; 3] = [[-2, -9, -2, -9], [0, 0, 0, 0], [8, 2, 9, 2]];

pub struct VelocitySystem;

impl<'a> System<'a> for VelocitySystem {
    type SystemData = (
        ReadStorage<'a, Intent>,
        ReadStorage<'a, TouchingBoundary>,
        WriteStorage<'a, Velocity>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(
        &mut self,
        (intent, touching_boundary, mut velocity, mut walking_state): Self::SystemData,
    ) {
        use specs::Join;

        for (intent, touching_boundary, velocity, walking_state) in (
            &intent,
            &touching_boundary,
            &mut velocity,
            &mut walking_state,
        )
            .join()
        {
            match intent.command {
                Command::Move { mut x, mut y } => {
                    match x {
                        XAxis::Right => walking_state.direction = Facing::Right,
                        XAxis::Left => walking_state.direction = Facing::Left,
                        _ => (),
                    }

                    if touching_boundary.left || touching_boundary.right {
                        x = XAxis::Centre;
                    }
                    if touching_boundary.top || touching_boundary.bottom {
                        y = YAxis::Centre;
                    }
                    let step = ((walking_state.step + 1) % 4);

                    velocity.x = X_STEP_SIZES[(x as i32 + 1) as usize][step as usize];
                    velocity.y = Y_STEP_SIZES[(y as i32 + 1) as usize][step as usize];
                    walking_state.step = step;
                }
                _ => {
                    velocity.x = 0;
                    velocity.y = 0;
                }
            }
        }
    }
}
