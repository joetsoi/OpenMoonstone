use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct RenderOrder {
    pub depth: usize,
}
