use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Controller, Position};

pub struct Movement;

impl<'a> System<'a> for Movement {
    type SystemData = (ReadStorage<'a, Controller>, WriteStorage<'a, Position>);

    fn run(&mut self, (controller, mut position): Self::SystemData) {
        use specs::Join;

        for (controller, position) in (&controller, &mut position).join() {
            position.x = (position.x as i32 + controller.x) as u32;
            position.y = (position.y as i32 - controller.y) as u32;
        }
    }
}
