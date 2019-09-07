use specs::{Component, Entity, VecStorage};
use specs_derive::*;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct AiState {
    pub class: String,
    pub target: Option<Entity>,
    pub close_range: u32,
    pub long_range: u32,
    pub y_range: u32,
}
