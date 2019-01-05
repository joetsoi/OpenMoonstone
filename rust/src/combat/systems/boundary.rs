use specs::{ReadExpect, ReadStorage, System, WriteStorage};

use crate::combat::components::{Intent, Position, Velocity};

struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

// TODO: change to be SystemData
const LAIR_BOUNDARY: Rect = Rect {
    x: 0,   //10,
    y: 0,   //30,
    w: 320, // - 10,
    h: 155, // - 30,
};

#[derive(Debug)]
pub struct TopBoundary {
    pub y: i32,
}

impl Default for TopBoundary {
    fn default() -> TopBoundary {
        TopBoundary { y: 30 }
    }
}

pub struct RestrictMovementToBoundary;
// takes a velocity and restricts velocity if the resulting movement would
// collide with a boundary

impl<'a> System<'a> for RestrictMovementToBoundary {
    type SystemData = (
        ReadExpect<'a, TopBoundary>,
        ReadStorage<'a, Position>,
        // anything which can take commands is bounded to the screen.
        // TODO: what happens with off screen (trogg war beasts) enemies?
        ReadStorage<'a, Intent>,
        WriteStorage<'a, Velocity>,
    );
    fn run(&mut self, (top_boundary, position, intent, mut velocity): Self::SystemData) {
        use specs::Join;
        for (position, _, velocity) in (&position, &intent, &mut velocity).join() {
            let new_x = position.x as i32 + velocity.x;
            if new_x < LAIR_BOUNDARY.x && velocity.x < 0
                || new_x > LAIR_BOUNDARY.w && velocity.x > 0
            {
                velocity.x = 0;
            }

            let new_y = position.y as i32 - velocity.y;
            if new_y < top_boundary.y && velocity.y < 0 || new_y > LAIR_BOUNDARY.h && velocity.y > 0
            {
                velocity.y = 0;
            }
        }
    }
}
