use specs::{storage::BTreeStorage, Component, Entity, FlaggedStorage, VecStorage};
use specs_derive::*;

#[derive(Debug)]
pub struct Interactable {
    pub target: Entity,
}

impl Component for Interactable {
    type Storage = FlaggedStorage<Self, BTreeStorage<Self>>;
}
