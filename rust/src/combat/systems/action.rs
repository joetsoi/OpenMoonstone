use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Action, Command, Intent, State};
use crate::combat::components::intent::{AttackType, DefendType};

pub struct ActionSystem;

impl<'a> System<'a> for ActionSystem {
    type SystemData = (ReadStorage<'a, Intent>, WriteStorage<'a, State>);

    fn run(&mut self, (intent, mut state): Self::SystemData) {
        use specs::Join;

        for (intent, state) in (&intent, &mut state).join() {
            match intent.command {
                Command::Attack(_attack_type) => {
                    match state.action {
                        Action::Idle | Action::Move {..} => {
                            state.action = Action::Attack(AttackType::Swing);
                            state.length = 0;
                            state.ticks = 0;
                        },
                        _ => (),
                    }
                },
                _ => (),
            }
        }
    }
}
