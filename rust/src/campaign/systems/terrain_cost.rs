/// Handles cost of knights moving across terrain
use specs::{Join, ReadExpect, ReadStorage, System, WriteStorage};

use crate::campaign::components::map_intent::MapCommand;
use crate::campaign::components::{HitBox, MapIntent, TimeSpentOnTerrain};
use crate::campaign::movement_cost::CampaignMap;
use crate::combat::components::Position;

pub struct TerrainCost;

impl<'a> System<'a> for TerrainCost {
    type SystemData = (
        ReadExpect<'a, CampaignMap>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, HitBox>,
        WriteStorage<'a, MapIntent>,
        WriteStorage<'a, TimeSpentOnTerrain>,
    );
    fn run(
        &mut self,
        (campaign_map, position, hitbox, mut intent, mut time_on_terrain): Self::SystemData,
    ) {
        for (position, hitbox, mut intent, mut time_on_terrain) in
            (&position, &hitbox, &mut intent, &mut time_on_terrain).join()
        {
            let x: i32 = position.x + (hitbox.w / 2) as i32;
            let y: i32 = position.y + hitbox.h as i32;
            let move_cost: u32 = campaign_map.movement_cost(x as u32, y as u32);
            if let MapCommand::Move { .. } = intent.command {
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
