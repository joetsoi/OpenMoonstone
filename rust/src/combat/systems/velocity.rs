use crate::combat::components::intent::{XAxis, YAxis};
use crate::combat::components::{
    Action,
    Command,
    Facing,
    Intent,
    State,
    UnitType,
    Velocity,
    WalkingState,
};
use crate::combat::resources::MoveDistances;
use specs::{ReadExpect, ReadStorage, System, WriteStorage};

pub const X_STEP_SIZES: [[i32; 4]; 3] = [[-25, -3, -23, -4], [0, 0, 0, 0], [25, 3, 23, 4]];
pub const Y_STEP_SIZES: [[i32; 4]; 3] = [[-2, -9, -2, -9], [0, 0, 0, 0], [8, 2, 9, 2]];

pub struct VelocitySystem;

impl<'a> System<'a> for VelocitySystem {
    type SystemData = (
        ReadExpect<'a, MoveDistances>,
        ReadStorage<'a, UnitType>,
        ReadStorage<'a, Intent>,
        WriteStorage<'a, State>,
        WriteStorage<'a, Velocity>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(
        &mut self,
        (move_data, unit_type, intent, mut state, mut velocity, mut walking_state): Self::SystemData,
    ) {
        use specs::Join;

        for (unit_type, intent, state, velocity, walking_state) in (
            &unit_type,
            &intent,
            &mut state,
            &mut velocity,
            &mut walking_state,
        )
            .join()
        {
            match state.action {
                Action::Idle | Action::Move { .. } => match intent.command {
                    Command::Move { x, y } => {
                        if x == XAxis::Centre && y == YAxis::Centre {
                            state.action = Action::Idle;
                            velocity.x = 0;
                            velocity.y = 0;
                        } else {
                            let walking_direction = match x {
                                XAxis::Right => Facing::Right,
                                XAxis::Left => Facing::Left,
                                _ => state.direction,
                            };
                            state.action = Action::Move { x, y };

                            let mut step = (walking_state.step + 1) % 4;
                            if walking_direction != state.direction {
                                // if we have an ai player, then they are always
                                // facing the player, so the step sizes don't
                                // match the animation, shifting this fixes that
                                // this wasn't fixed in the original and the
                                // forward facing animations were off by 1
                                //
                                // TODO: come back to this when we add other enemy
                                // types.
                                step = (step + 1) % 4;
                            }
                            match move_data.distances.get(&unit_type.name) {
                                Some(step_sizes) => {
                                    velocity.y =
                                        step_sizes.y_axis[(y as i32 + 1) as usize][step as usize].j;
                                    velocity.x =
                                        step_sizes.y_axis[(x as i32 + 1) as usize][step as usize].i;
                                    if x as i32 != 0 {
                                        velocity.x = step_sizes.x_axis[(x as i32 + 1) as usize]
                                            [step as usize]
                                            .i;
                                    };
                                }
                                None => {
                                    eprintln!("Couldn't find {} in movement.ron", unit_type.name)
                                }
                            }
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
            if let Action::Move { mut x, mut y } = state.action {
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
        }
    }
}
