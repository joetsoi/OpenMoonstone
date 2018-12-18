use specs::{System, WriteStorage};

use crate::combat::components::{Action, State};

pub struct StateUpdater;

impl<'a> System<'a> for StateUpdater {
    type SystemData = (WriteStorage<'a, State>,);

    fn run(&mut self, (mut state,): Self::SystemData) {
        use specs::Join;

        for state in (&mut state).join() {
            match state.action {
                Action::Attack(..) | Action::Hit(..) | Action::AttackRecovery => {
                    state.ticks += 1;
                    if state.ticks == state.length && state.length != 0 {
                        // assuming: that all states that match this arm have a
                        // length > 1 means we don't need to update state.length
                        // in the ResolveCollisions with the animation length
                        // whenever that system changes state of an entity.
                        if state.ticks > 1 {
                            state.action = Action::Idle;
                        }
                    }
                }
                _ => (),
            }
        }
    }
}
