use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{XAxis, YAxis};
use crate::combat::components::{
    Action, Command, Facing, Intent, State, TouchingBoundary, Velocity, WalkingState,
};

pub const X_STEP_SIZES: [[i32; 4]; 3] = [[-25, -3, -23, -4], [0, 0, 0, 0], [25, 3, 23, 4]];
pub const Y_STEP_SIZES: [[i32; 4]; 3] = [[-2, -9, -2, -9], [0, 0, 0, 0], [8, 2, 9, 2]];

pub struct VelocitySystem;

impl<'a> System<'a> for VelocitySystem {
    type SystemData = (
        ReadStorage<'a, Intent>,
        ReadStorage<'a, TouchingBoundary>,
        WriteStorage<'a, State>,
        WriteStorage<'a, Velocity>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(
        &mut self,
        (intent, touching_boundary, mut state, mut velocity, mut walking_state): Self::SystemData,
    ) {
        use specs::Join;

        for (intent, touching_boundary, state, velocity, walking_state) in (
            &intent,
            &touching_boundary,
            &mut state,
            &mut velocity,
            &mut walking_state,
        )
            .join()
        {
            match state.action {
                Action::Idle | Action::Move { .. } => match intent.command {
                    Command::Move { x, y } => {
                        match x {
                            XAxis::Right => state.direction = Facing::Right,
                            XAxis::Left => state.direction = Facing::Left,
                            _ => (),
                        }

                        let mut move_x = x;
                        if touching_boundary.left || touching_boundary.right {
                            move_x = XAxis::Centre;
                        }

                        let mut move_y = y;
                        if touching_boundary.top || touching_boundary.bottom {
                            move_y = YAxis::Centre;
                        }

                        if move_x == XAxis::Centre && move_y == YAxis::Centre {
                            state.action = Action::Idle;
                            velocity.x = 0;
                            velocity.y = 0;
                        } else {
                            state.action = Action::Move {
                                x: move_x,
                                y: move_y,
                            };

                            let step = ((walking_state.step + 1) % 4);
                            velocity.x = X_STEP_SIZES[(x as i32 + 1) as usize][step as usize];
                            velocity.y = Y_STEP_SIZES[(y as i32 + 1) as usize][step as usize];
                            walking_state.step = step;
                        }
                    }
                    _ => {
                        state.action = Action::Idle;
                        velocity.x = 0;
                        velocity.y = 0;
                    }
                },
                _ => {
                    velocity.x = 0;
                    velocity.y = 0;
                }
            }
        }
    }
}
