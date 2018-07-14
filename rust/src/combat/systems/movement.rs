use specs::{ReadStorage, System};

use crate::combat::components::Position;

pub struct Movement;

impl<'a> System<'a> for Movement {
    type SystemData = ReadStorage<'a, Position>;

    fn run(&mut self, position: Self::SystemData) {
        use specs::Join;

        for position in position.join() {
            println!("Hello, {:?}", &position);
        }
    }
}
