use specs::{Join, ReadStorage, System, WriteExpect, WriteStorage};

use crate::campaign::components::map_intent::MapCommand;
use crate::campaign::components::{Endurance, MapIntent};
use crate::scenes::map::TurnOver;

pub struct EnduranceTracker;

impl<'a> System<'a> for EnduranceTracker {
    type SystemData = (
        WriteExpect<'a, TurnOver>,
        ReadStorage<'a, MapIntent>,
        WriteStorage<'a, Endurance>,
    );

    fn run(&mut self, (mut turn_over, intent, mut endurance): Self::SystemData) {
        for (intent, endurance) in (&intent, &mut endurance).join() {
            if let MapCommand::Move { x, y } = intent.command {
                endurance.used += 1;
                if endurance.used >= endurance.max {
                    turn_over.0 = true;
                }
            }
        }
    }
}
