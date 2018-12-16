use specs::{System, WriteStorage};

use crate::combat::components::{Action, State};

pub struct StateUpdater;

impl<'a> System<'a> for StateUpdater {
    type SystemData = (WriteStorage<'a, State>,);

    fn run(&mut self, (mut state,): Self::SystemData) {
        use specs::Join;

        for state in (&mut state).join() {
            match state.action {
                Action::Attack { .. } | Action::Hit { .. } => {
                    state.ticks += 1;
                    if state.ticks == state.length && state.length != 0 {
                        state.action = Action::Idle;
                    }
                }
                _ => (),
            }
        }
    }
}
