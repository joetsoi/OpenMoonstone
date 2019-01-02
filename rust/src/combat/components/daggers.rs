use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct DaggersInventory {
    pub count: u32,
    pub max: u32,
}

impl Default for DaggersInventory {
    fn default() -> DaggersInventory {
        DaggersInventory { count: 10, max: 10 }
    }
}
