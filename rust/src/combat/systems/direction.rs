use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::XAxis;
use crate::combat::components::movement::get_distance;
use crate::combat::components::{
    Action, AiState, Command, Facing, Intent, Position, State,
};

pub struct PlayerDirection;

impl<'a> System<'a> for PlayerDirection {
    type SystemData = (
        ReadStorage<'a, Intent>,
        WriteStorage<'a, State>,
    );

    fn run(&mut self, (intent, mut state): Self::SystemData) {
        use specs::Join;

        for (intent,  state) in (&intent, &mut state).join() {
            match state.action {
                Action::Idle | Action::Move { .. } => match intent.command {
                    Command::Move { x, y: _ } => match x {
                        XAxis::Right => state.direction = Facing::Right,
                        XAxis::Left => state.direction = Facing::Left,
                        _ => (),
                    },
                    _ => (),
                },
                _ => (),
            }
        }
    }
}

pub struct AiDirection;

impl<'a> System<'a> for AiDirection {
    type SystemData = (
        ReadStorage<'a, Intent>,
        ReadStorage<'a, AiState>,
        ReadStorage<'a, Position>,
        WriteStorage<'a, State>,
    );

    fn run(&mut self, (intent, ai_state, position_storage, mut state): Self::SystemData) {
        use specs::Join;

        for (intent, ai_state, position, state) in
            (&intent, &ai_state, &position_storage, &mut state).join()
        {
            match state.action {
                Action::Idle | Action::Move { .. } => match intent.command {
                    Command::Move { .. } => {
                        let target_position: Option<&Position> =
                            ai_state.target.and_then(|t| position_storage.get(t));
                        if let Some(target_position) = target_position {
                            let delta = get_distance(position, target_position);
                            if delta.x < 0 {
                                state.direction = Facing::Right;
                            } else {
                                state.direction = Facing::Left;
                            }
                        }
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }
}
