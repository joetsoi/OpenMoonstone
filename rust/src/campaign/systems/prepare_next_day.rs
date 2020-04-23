use specs::{Join, ReadStorage, System, WriteExpect, WriteStorage};

use crate::campaign::components::Endurance;
use crate::scenes::map::TurnOver;

pub struct PrepareNextDay;

impl<'a> System<'a> for PrepareNextDay {
    type SystemData = (WriteExpect<'a, TurnOver>, WriteStorage<'a, Endurance>);

    fn run(&mut self, (mut turn_over, mut endurance): Self::SystemData) {
        if turn_over.0 == true {
            for (endurance) in (&mut endurance).join() {
                endurance.used = 0;
            }
            turn_over.0 = false;
        }
    }
}
