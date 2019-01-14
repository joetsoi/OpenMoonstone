use rand::prelude::*;
use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::direction::Facing;
use crate::combat::components::intent::{AttackType, DefendType, XAxis, YAxis};
use crate::combat::components::movement::get_distance;
use crate::combat::components::state::Action;
use crate::combat::components::{
    AiState, Command, Controller, DaggersInventory, Intent, Position, State,
};
use crate::rect::Point;

const ACTION_CHANCE: [u32; 19] = [20, 10, 8, 7, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5];

pub struct BlackKnightAi;

impl<'a> System<'a> for BlackKnightAi {
    type SystemData = (
        ReadStorage<'a, AiState>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, State>,
        ReadStorage<'a, DaggersInventory>,
        WriteStorage<'a, Intent>,
    );

    fn run(
        &mut self,
        (ai_storage, position_storage, state_storage, dagger_storage, mut intent_storage): Self::SystemData,
    ) {
        use specs::Join;

        for (ai, position, state, daggers, intent) in (
            &ai_storage,
            &position_storage,
            &state_storage,
            &dagger_storage,
            &mut intent_storage,
        )
            .join()
        {
            let target_position: Option<&Position> =
                ai.target.and_then(|t| position_storage.get(t));
            let target_state: Option<&State> = ai.target.and_then(|t| state_storage.get(t));

            if let (Some(target_state), Some(target_position)) = (target_state, target_position) {
                let delta = get_distance(position, target_position);
                let movement = get_movement(ai, &delta);
                let command = match movement {
                    Command::Move {
                        x: _,
                        y: YAxis::Centre,
                    } => {
                        let mut command = do_block(0, &delta, state, target_state);
                        if command.is_none() {
                            command = do_attack(0, &delta, daggers.count);
                        }
                        command
                    }
                    _ => None,
                };
                match command {
                    Some(command) => intent.command = command,
                    None => intent.command = movement,
                }
            } else {
                intent.command = Command::Idle;
            }
        }
    }
}

/// Calculates whether an ai controlled entity should move
fn get_movement(ai: &AiState, delta: &Point) -> Command {
    let y_axis = match delta.y.abs() {
        y if y > ai.y_range as i32 => match delta.y {
            d if d <= 0 => YAxis::Down,
            _ => YAxis::Up,
        },
        _ => YAxis::Centre,
    };
    let x_axis = match delta.x.abs() {
        x if x < ai.close_range as i32 => match delta.x {
            d if d < 0 => XAxis::Left,
            _ => XAxis::Right,
        },
        x if x > ai.long_range as i32 => match delta.x {
            d if d < 0 => XAxis::Right,
            _ => XAxis::Left,
        },
        _ => XAxis::Centre,
    };
    Command::Move {
        x: x_axis,
        y: y_axis,
    }
}

fn do_block(
    chance_index: usize,
    delta: &Point,
    state: &State,
    target_state: &State,
) -> Option<Command> {
    let mut rng = rand::thread_rng();
    let chance = rng.gen_range(0, 100);

    if chance >= ACTION_CHANCE[chance_index] || state.direction == target_state.direction {
        return None;
    }

    match target_state.action {
        Action::Attack(AttackType::Swing) => match delta.x {
            x if x <= 120 => Some(Command::Defend(DefendType::Block)),
            _ => None,
        },
        Action::Attack(AttackType::Chop) => match delta.x {
            x if x <= 120 => Some(Command::Defend(DefendType::Dodge)),
            _ => None,
        },
        _ => None,
    }
}

fn do_attack(chance_index: usize, delta: &Point, dagger_count: u32) -> Option<Command> {
    let mut rng = rand::thread_rng();
    let chance = rng.gen_range(0, 100);

    if chance < ACTION_CHANCE[chance_index] {
        return None;
    }

    match delta.x.abs() {
        x if x <= 90 => Some(Command::Attack(AttackType::Swing)),
        x if x <= 95 && x > 90 => Some(Command::Attack(AttackType::Chop)),
        x if x <= 100 && x > 95 => match dagger_count {
            d if d > 0 => Some(Command::Attack(AttackType::ThrowDagger)),
            _ => Some(Command::Attack(AttackType::Thrust)),
        },
        _ => match dagger_count {
            d if d > 0 => Some(Command::Attack(AttackType::ThrowDagger)),
            _ => None,
        },
    }
}
