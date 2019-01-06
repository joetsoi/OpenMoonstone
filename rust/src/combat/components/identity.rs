use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct UnitType {
    pub name: String,
}
