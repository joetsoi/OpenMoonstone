use specs::{Read, ReadStorage, System, WriteStorage};

use crate::combat::components::{Collision, Position, State};
use crate::files::collide::CollisionBoxes;

pub struct UpdateBoundingBoxes;

impl<'a> System<'a> for UpdateBoundingBoxes {
    type SystemData = (
        Read<'a, CollisionBoxes>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, State>,
        WriteStorage<'a, Collision>,
    );

    fn run(&mut self, (collision_boxes, position, state, mut collision): Self::SystemData) {
        use specs::Join;
        let collision_data = &collision_boxes.data;
        for (position, state, collision) in (&position, &state, &mut collision).join() {
            println!("{:?}", state);
        }
    }
}
