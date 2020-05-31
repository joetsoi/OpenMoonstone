use specs::{Entities, ReadStorage, System, WriteExpect, WriteStorage};

use crate::combat::components::{Action, Health, MustLive, State};

pub struct EntityDeath;

impl<'a> System<'a> for EntityDeath {
    type SystemData = (
        ReadStorage<'a, Health>,
        WriteStorage<'a, State>,
        Entities<'a>,
    );

    fn run(&mut self, (health, mut state, entities): Self::SystemData) {
        use specs::Join;

        for (health, state, entity) in (&health, &mut state, &entities).join() {
            match state.action {
                Action::Death(_) => (),
                Action::Dead => {
                    entities.delete(entity).expect("failed to delete entity");
                }
                _ => {
                    if health.points <= 0 {
                        state.action = Action::Death("death".to_string());
                        state.ticks = 0;
                        // the death animations have the wrong direction
                        state.direction = state.direction.flip();
                    }
                }
            }
        }
    }
}

pub struct CombatDone(pub bool);
pub struct CheckEndOfCombat;

impl<'a> System<'a> for CheckEndOfCombat {
    type SystemData = (WriteExpect<'a, CombatDone>, ReadStorage<'a, MustLive>);

    fn run(&mut self, (mut combat_done, must_live): Self::SystemData) {
        use specs::Join;
        // let live_entity_count = (&health, &must_live)
        let live_entity_count = (&must_live)
            .join()
            // .filter(|(h, _)| h.points > 0)
            .fold(0, |acc, _| acc + 1);

        if live_entity_count <= 1 {
            combat_done.0 = true;
        }
    }
}
