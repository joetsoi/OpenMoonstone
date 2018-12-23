use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Action, Health, State};

pub struct EntityDeath;

impl<'a> System<'a> for EntityDeath {
    type SystemData = (ReadStorage<'a, Health>, WriteStorage<'a, State>);

    fn run(&mut self, (health, mut state): Self::SystemData) {
        use specs::Join;

        for (health, state) in (&health, &mut state).join() {
            match state.action {
                Action::Death | Action::Dead => (),
                _ => {
                    if health.points <= 0 {
                        state.action = Action::Death;
                        state.ticks = 0;
                        // the death animations have the wrong direction
                        state.direction = state.direction.flip();
                    }
                }
            }
        }
    }
}
