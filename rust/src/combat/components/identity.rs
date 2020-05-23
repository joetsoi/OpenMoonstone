use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct UnitType {
    // TODO change this to string reference that lives as long as the Spawner?
    pub name: String,
}
