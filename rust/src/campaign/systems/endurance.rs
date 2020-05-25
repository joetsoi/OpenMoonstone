use specs::{Join, ReadStorage, System, WriteExpect, WriteStorage};

use crate::campaign::components::map_intent::MapCommand;
use crate::campaign::components::{Endurance, MapIntent};
use crate::combat::components::Controller;
use crate::scenes::map::OrderedEntities;

pub struct EnduranceTracker;

impl<'a> System<'a> for EnduranceTracker {
    type SystemData = (
        WriteExpect<'a, OrderedEntities>,
        // WriteExpect<'a, TurnOver>,
        ReadStorage<'a, MapIntent>,
        ReadStorage<'a, Controller>,
        WriteStorage<'a, Endurance>,
    );

    fn run(&mut self, (mut ordered_entities, intent, controller, mut endurance): Self::SystemData) {
        for (intent, _, endurance) in (&intent, &controller, &mut endurance).join() {
            if let MapCommand::Move{ .. } = intent.command {
                endurance.used += 1;
                if endurance.used >= endurance.max {
                    ordered_entities.player_done = true;
                }
            }
        }
    }
}
