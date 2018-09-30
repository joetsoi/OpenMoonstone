use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Action {
    pub name: String,
    pub ticks: u32,
}
