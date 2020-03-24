/// Handles cost of knights moving across terrain
use specs::{Join, ReadExpect, ReadStorage, System, WriteStorage};

use crate::campaign::components::map_intent::MapCommand;
use crate::campaign::components::{MapIntent, TimeSpentOnTerrain};
use crate::campaign::movement_cost::CampaignMap;
use crate::combat::components::Position;

pub struct TerrainCost;

impl<'a> System<'a> for TerrainCost {
    type SystemData = (
        ReadExpect<'a, CampaignMap>,
        ReadStorage<'a, Position>,
        WriteStorage<'a, MapIntent>,
        WriteStorage<'a, TimeSpentOnTerrain>,
    );
    fn run(&mut self, (campaign_map, position, mut intent, mut time_on_terrain): Self::SystemData) {
        for (position, mut intent, mut time_on_terrain) in
            (&position, &mut intent, &mut time_on_terrain).join()
        {
            let move_cost: u32 = campaign_map.movement_cost(position.x as u32, position.y as u32);
            if let MapCommand::Move { x, y } = intent.command {
                if time_on_terrain.count < move_cost {
                    time_on_terrain.count += 1;
                    intent.command = MapCommand::Idle;
                } else {
                    time_on_terrain.count = 0;
                }
            }
        }
    }
}
