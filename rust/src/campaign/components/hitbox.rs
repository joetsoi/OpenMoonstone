use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct HitBox {
    pub w: u32,
    pub h: u32,
}
