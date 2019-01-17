use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Position, Velocity};

pub struct Movement;

impl<'a> System<'a> for Movement {
    type SystemData = (ReadStorage<'a, Velocity>, WriteStorage<'a, Position>);

    fn run(&mut self, (velocity, mut position): Self::SystemData) {
        use specs::Join;

        for (velocity, position) in (&velocity, &mut position).join() {
            position.x += velocity.x;
            position.y += velocity.y;
        }
    }
}
