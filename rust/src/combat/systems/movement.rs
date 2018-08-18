use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Position, Velocity, WalkingState};

pub struct Movement;

impl<'a> System<'a> for Movement {
    type SystemData = (
        ReadStorage<'a, Velocity>,
        WriteStorage<'a, Position>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(&mut self, (velocity, mut position, mut walking_state): Self::SystemData) {
        use specs::Join;

        for (velocity, position, walking_state) in
            (&velocity, &mut position, &mut walking_state).join()
        {
            position.x = (position.x as i32 + velocity.x) as u32;
            position.y = (position.y as i32 - velocity.y) as u32;
        }
    }
}
