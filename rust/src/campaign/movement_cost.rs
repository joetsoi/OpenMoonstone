use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CampaignMap {
    movement_cost: Vec<Vec<u32>>,
}

impl CampaignMap {
    pub fn movement_cost(&self, x: u32, y: u32) -> u32 {
        let x_lookup: usize = x as usize / 8;
        let y_lookup: usize = y as usize / 8;
        self.movement_cost[y_lookup][x_lookup]
    }
}
