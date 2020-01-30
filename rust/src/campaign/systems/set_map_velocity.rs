use specs::{ReadStorage, System, WriteStorage};

use crate::campaign::components::MapIntent;
use crate::campaign::components::map_intent::{MapCommand, XAxis, YAxis};
use crate::combat::components::{Velocity};

pub struct SetMapVelocity;

impl<'a> System<'a> for SetMapVelocity {
    type SystemData = (ReadStorage<'a, MapIntent>, WriteStorage<'a, Velocity>);

    fn run(&mut self, (intent, mut velocity): Self::SystemData) {
        use specs::Join;

        for (intent, velocity) in (&intent, &mut velocity).join() {
            match intent.command {
                MapCommand::Move { x, y } => {
                    if x == XAxis::Centre && y == YAxis::Centre {
                        velocity.x = 0;
                        velocity.y = 0;
                    } else {
                        velocity.x = x as i32;
                        velocity.y = y as i32;
                    }
                }
                _ => {
                    velocity.x = 0;
                    velocity.y = 0;
                }
            }
        }
    }
}
