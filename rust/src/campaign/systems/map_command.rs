/// Contains the system that converts user input into entity movement commands.
use specs::{ReadStorage, System, WriteStorage};

use crate::campaign::components::map_intent::{MapCommand, XAxis, YAxis};
use crate::campaign::components::MapIntent;
use crate::combat::components::Controller;

pub struct MapCommander;

impl<'a> System<'a> for MapCommander {
    type SystemData = (ReadStorage<'a, Controller>, WriteStorage<'a, MapIntent>);

    fn run(&mut self, (controller, mut intent): Self::SystemData) {
        use specs::Join;

        for (controller, intent) in (&controller, &mut intent).join() {
            if controller.x == 0 && controller.y == 0 {
                intent.command = MapCommand::Idle;
            } else if !controller.fire {
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
                intent.command = MapCommand::Move { x, y };
            } else {
                intent.command = MapCommand::Interact;
            }
        }
    }
}
