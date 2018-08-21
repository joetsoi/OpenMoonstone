use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{XAxis, YAxis};
use crate::combat::components::{
    Command, Intent, Position, TouchingBoundary, Velocity, WalkingState,
};

struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

const LAIR_BOUNDARY: Rect = Rect {
    x: 10, //10,
    y: 0,  //30,
    w: 320 - 10,
    h: 155, // - 30,
};
pub struct Boundary;

impl<'a> System<'a> for Boundary {
    type SystemData = (
        ReadStorage<'a, Position>,
        ReadStorage<'a, Velocity>,
        ReadStorage<'a, Intent>,
        WriteStorage<'a, TouchingBoundary>,
    );

    fn run(&mut self, (position, velocity, intent, mut touching_boundary): Self::SystemData) {
        use specs::Join;

        for (position, velocity, intent, touching_boundary) in
            (&position, &velocity, &intent, &mut touching_boundary).join()
        {
            let new_x = position.x as i32 + velocity.x;
            if let Command::Move { x, y } = intent.command {
                if (new_x < LAIR_BOUNDARY.x && x == XAxis::Left) {
                    touching_boundary.left = true;
                } else if (new_x > LAIR_BOUNDARY.w && x == XAxis::Right) {
                    touching_boundary.right = true;
                } else {
                    touching_boundary.left = false;
                    touching_boundary.right = false;
                }

                let new_y = position.y as i32 - velocity.y;
                if (new_y < LAIR_BOUNDARY.y && y == YAxis::Up) {
                    touching_boundary.top = true;
                } else if (new_y > LAIR_BOUNDARY.h && y == YAxis::Down) {
                    touching_boundary.bottom = true;
                } else {
                    touching_boundary.top = false;
                    touching_boundary.bottom = false;
                }
            }
        }
    }
}
