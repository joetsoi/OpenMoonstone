use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Controller, Position, Velocity, WalkingState};

struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

const LAIR_BOUNDARY: Rect = Rect {
    x: 0,   //10,
    y: 0,   //30,
    w: 320, // - 10,
    h: 155, // - 30,
};

pub struct Boundary;

impl<'a> System<'a> for Boundary {
    type SystemData = (
        ReadStorage<'a, Position>,
        ReadStorage<'a, Velocity>,
        WriteStorage<'a, Controller>,
        WriteStorage<'a, WalkingState>,
    );

    fn run(&mut self, (position, velocity, mut controller, mut walking_state): Self::SystemData) {
        use specs::Join;

        for (position, velocity, controller, walking_state) in
            (&position, &velocity, &mut controller, &mut walking_state).join()
        {
            let new_x = position.x as i32 + velocity.x;
            if (new_x < LAIR_BOUNDARY.x && controller.x == -1)
                || (new_x > LAIR_BOUNDARY.w && controller.x == 1)
            {
                controller.x = 0;
            }
            let new_y = position.y as i32 - velocity.y;
            if (new_y < LAIR_BOUNDARY.y && controller.y == -1)
                || (new_y > LAIR_BOUNDARY.h && controller.y == 1)
            {
                controller.y = 0;
            }
            //println!("{:?} {:?}", controller, position);
        }
    }
}
