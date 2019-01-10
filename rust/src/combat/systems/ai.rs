use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::direction::Facing;
use crate::combat::components::intent::{AttackType, DefendType, XAxis, YAxis};
use crate::combat::components::{AiState, Command, Controller, Intent, Position, State};

pub struct BlackKnightAi;

impl<'a> System<'a> for BlackKnightAi {
    type SystemData = (
        ReadStorage<'a, AiState>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, State>,
        WriteStorage<'a, Intent>,
    );

    fn run(
        &mut self,
        (ai_storage, position_storage, state_storage, mut intent_storage): Self::SystemData,
    ) {
        use specs::Join;

        for (ai, position, state, intent) in (
            &ai_storage,
            &position_storage,
            &state_storage,
            &mut intent_storage,
        )
            .join()
        {
            let target_position: Option<&Position> =
                ai.target.and_then(|t| position_storage.get(t));
            let state: Option<&State> = ai.target.and_then(|t| state_storage.get(t));

            let (x_delta, y_delta) = match target_position {
                Some(target_position) => (
                    position.x - target_position.x,
                    position.y - target_position.y,
                ),
                None => (0, 0),
            };

            let y_axis = match y_delta.abs() {
                y if y > ai.y_range as i32 => match y_delta {
                    d if d <= 0 => YAxis::Down,
                    _ => YAxis::Up,
                },
                _ => YAxis::Centre,
            };
            let x_axis = match x_delta.abs() {
                x if x < ai.close_range as i32 => match x_delta {
                    d if d < 0 => XAxis::Left,
                    _ => XAxis::Right,
                },
                x if x > ai.long_range as i32 => match x_delta {
                    d if d < 0 => XAxis::Right,
                    _ => XAxis::Left,
                },
                _ => XAxis::Centre,
            };
            intent.command = Command::Move {
                x: x_axis,
                y: y_axis,
            };
        }
    }
}
