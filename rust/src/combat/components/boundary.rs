use specs::VecStorage;
use specs_derive::*;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct TouchingBoundary {
    pub top: bool,
    pub bottom: bool,
    pub left: bool,
    pub right: bool,
}
