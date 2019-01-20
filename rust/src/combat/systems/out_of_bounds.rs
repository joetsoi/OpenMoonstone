use specs::{Entities, ReadStorage, System};

use crate::combat::components::Position;

pub struct OutOfBounds;

impl<'a> System<'a> for OutOfBounds {
    type SystemData = (ReadStorage<'a, Position>, Entities<'a>);

    fn run(&mut self, (position_storage, entities): Self::SystemData) {
        use specs::Join;

        for (position, entity) in (&position_storage, &*entities).join() {
            // TODO: change these hardcoded values?
            if position.x < -100 || position.x > 420 {
                entities.delete(entity);
            }
        }
    }
}
