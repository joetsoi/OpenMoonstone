use specs::{ReadExpect, ReadStorage, System, WriteStorage};

use crate::campaign::components::MapIntent;
use crate::combat::components::{Position, Velocity};

struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

#[derive(Debug)]
pub struct Boundary {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Default for Boundary {
    fn default() -> Boundary {
        Boundary {
            x: 0,
            y: 30,
            w: 320,
            h: 150,
        }
    }
}

pub struct RestrictMovementToMapBoundary;
// takes a velocity and restricts velocity if the resulting movement would
// collide with a boundary

impl<'a> System<'a> for RestrictMovementToMapBoundary {
    type SystemData = (
        ReadExpect<'a, Boundary>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, MapIntent>,
        WriteStorage<'a, Velocity>,
    );
    fn run(&mut self, (boundary, position, intent, mut velocity): Self::SystemData) {
        use specs::Join;
        for (position, _, velocity) in (&position, &intent, &mut velocity).join() {
            let new_x = position.x as i32 + velocity.x;
            if new_x < boundary.x && velocity.x < 0 || new_x > boundary.w && velocity.x > 0 {
                velocity.x = 0;
            }

            let new_y = position.y as i32 - velocity.y;
            if new_y < boundary.y && velocity.y < 0 || new_y > boundary.h && velocity.y > 0 {
                velocity.y = 0;
            }
        }
    }
}
