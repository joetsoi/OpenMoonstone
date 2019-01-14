use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{XAxis, YAxis};
use crate::combat::components::{Action, Command, Facing, Intent, State, Velocity, WalkingState};

pub const X_STEP_SIZES: [[i32; 4]; 3] = [[-25, -3, -23, -4], [0, 0, 0, 0], [25, 3, 23, 4]];
pub const Y_STEP_SIZES: [[i32; 4]; 3] = [[-2, -9, -2, -9], [0, 0, 0, 0], [8, 2, 9, 2]];

pub struct VelocitySystem;

impl<'a> System<'a> for VelocitySystem {
    type SystemData = (
        ReadStorage<'a, Intent>,
        WriteStorage<'a, State>,
        WriteStorage<'a, Velocity>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(&mut self, (intent, mut state, mut velocity, mut walking_state): Self::SystemData) {
        use specs::Join;

        for (intent, state, velocity, walking_state) in
            (&intent, &mut state, &mut velocity, &mut walking_state).join()
        {
            match state.action {
                Action::Idle | Action::Move { .. } => match intent.command {
                    Command::Move { x, y } => {
                        // match x {
                        //     XAxis::Right => state.direction = Facing::Right,
                        //     XAxis::Left => state.direction = Facing::Left,
                        //     _ => (),
                        // }
                        if x == XAxis::Centre && y == YAxis::Centre {
                            state.action = Action::Idle;
                            velocity.x = 0;
                            velocity.y = 0;
                        } else {
                            state.action = Action::Move { x, y };

                            let step = (walking_state.step + 1) % 4;
                            velocity.x = X_STEP_SIZES[(x as i32 + 1) as usize][step as usize];
                            velocity.y = Y_STEP_SIZES[(y as i32 + 1) as usize][step as usize];
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

pub struct ConfirmVelocity;
// If an entity has a non zero velocity, set movement in State,
// update the walking state step
// This is used after VelocitySystem is piped through RestrictMovementBoundry
// and check entity collision, those two systems might prevent movement
// so we want to update the final velocity here.

impl<'a> System<'a> for ConfirmVelocity {
    type SystemData = (
        ReadStorage<'a, Velocity>,
        WriteStorage<'a, State>,
        WriteStorage<'a, WalkingState>,
    );
    fn run(&mut self, (velocity, mut state, mut walking_state): Self::SystemData) {
        use specs::Join;
        for (velocity, state, walking_state) in (&velocity, &mut state, &mut walking_state).join() {
            match state.action {
                Action::Move { mut x, mut y } => {
                    if velocity.x == 0 {
                        x = XAxis::Centre;
                    }
                    if velocity.y == 0 {
                        y = YAxis::Centre;
                    }
                    if x == XAxis::Centre && y == YAxis::Centre {
                        state.action = Action::Idle;
                    } else {
                        walking_state.step = (walking_state.step + 1) % 4;
                    }
                }
                _ => (),
            }
        }
    }
}
