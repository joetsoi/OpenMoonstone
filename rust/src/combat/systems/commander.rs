use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{Command, Controller, Intent};
use crate::combat::components::intent::{XAxis, YAxis};

pub struct Commander;

impl<'a> System<'a> for Commander {
    type SystemData = (ReadStorage<'a, Controller>, WriteStorage<'a, Intent>);

    fn run(&mut self, (controller, mut intent): Self::SystemData) {
        use specs::Join;

        for (controller, intent) in (&controller, &mut intent).join() {
            if controller.x == 0 && controller.y == 0 {
                intent.command = Command::Idle;
            } else {
                let x = match controller.x {
                    -1 => XAxis::Left,
                    1 => XAxis::Right,
                    _ => XAxis::Centre,
                };
                let y = match controller.y {
                    -1 => YAxis::Up,
                    1 => YAxis::Down,
                    _ => YAxis::Centre,

                };
                intent.command = Command::Move {
                    x: x,
                    y: y,
                };
            }
            //println!("{:?}", intent);
        }
    }
}
