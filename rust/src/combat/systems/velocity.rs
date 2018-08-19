use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Command, Facing, Intent, MoveCommand, Velocity, WalkingState};

pub const STEP_LEFT: [i32; 4] = [-25, -3, -23, -4];
pub const STEP_RIGHT: [i32; 4] = [25, 3, 23, 4];
pub const STEP_UP: [i32; 4] = [-2, -9, -2, -9];
pub const STEP_DOWN: [i32; 4] = [8, 2, 9, 2];
pub const NO_STEP: [i32; 4] = [0, 0, 0, 0];

lazy_static! {
    static ref move_to_step: HashMap<MoveCommand, (&'static [i32; 4], &'static [i32; 4])> = hashmap!{
        MoveCommand::TryMoveUp => (&NO_STEP, &STEP_UP),
        MoveCommand::TryMoveDown => (&NO_STEP, &STEP_DOWN),
        MoveCommand::TryMoveLeft => (&STEP_LEFT, &NO_STEP),
        MoveCommand::TryMoveRight => (&STEP_RIGHT, &NO_STEP),
        MoveCommand::TryMoveLeftUp => (&STEP_LEFT, &STEP_UP),
        MoveCommand::TryMoveRightUp => (&STEP_RIGHT, &STEP_UP),
        MoveCommand::TryMoveLeftDown => (&STEP_LEFT, &STEP_DOWN),
        MoveCommand::TryMoveRightDown => (&STEP_RIGHT, &STEP_DOWN),
    };
}

pub struct VelocitySystem;

impl<'a> System<'a> for VelocitySystem {
    type SystemData = (
        ReadStorage<'a, Intent>,
        WriteStorage<'a, Velocity>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(&mut self, (intent, mut velocity, mut walking_state): Self::SystemData) {
        use specs::Join;

        for (intent, velocity, walking_state) in (&intent, &mut velocity, &mut walking_state).join()
        {
            match intent.command {
                Command::Move(m) => {
                    let step_vector = move_to_step[&m];
                    let step = ((walking_state.step + 1) % 4);
                    velocity.x = step_vector.0[step as usize];
                    velocity.y = step_vector.1[step as usize];
                    walking_state.step = step;
                    match m {
                        MoveCommand::TryMoveLeft
                        | MoveCommand::TryMoveLeftUp
                        | MoveCommand::TryMoveLeftDown => walking_state.direction = Facing::Left,
                        MoveCommand::TryMoveRight
                        | MoveCommand::TryMoveRightUp
                        | MoveCommand::TryMoveRightDown => {
                            walking_state.direction = Facing::Right
                        }
                        _ => (),
                    }
                }
                _ => {
                    velocity.x = 0;
                    velocity.y = 0;
                }
            }
        }
    }
}
