use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Position, Velocity};

struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

// TODO: change to be SystemData
const LAIR_BOUNDARY: Rect = Rect {
    x: 0, //10,
    y: 0,  //30,
    w: 320,// - 10,
    h: 155, // - 30,
};

pub struct RestrictMovementToBoundary;
// takes a velocity and restricts velocity if the resulting movement would
// collide with a boundary

impl<'a> System<'a> for RestrictMovementToBoundary {
    type SystemData = (ReadStorage<'a, Position>, WriteStorage<'a, Velocity>);
    fn run(&mut self, (position, mut velocity): Self::SystemData) {
        use specs::Join;
        for (position, velocity) in (&position, &mut velocity).join() {
            let new_x = position.x as i32 + velocity.x;
            if new_x < LAIR_BOUNDARY.x && velocity.x < 0
                || new_x > LAIR_BOUNDARY.w && velocity.x > 0
            {
                velocity.x = 0;
            }

            let new_y = position.y as i32 - velocity.y;
            if new_y < LAIR_BOUNDARY.y && velocity.y < 0
                || new_y > LAIR_BOUNDARY.h && velocity.y > 0
            {
                velocity.y = 0;
            }
        }
    }
}
