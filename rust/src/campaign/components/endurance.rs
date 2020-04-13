use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Endurance {
    pub max: u32,
    pub used: u32,
}
// endurance * 2
// chainmail + 2
// battle armour + 4
// + 4 in general
//
// number of ticks = result << 4
