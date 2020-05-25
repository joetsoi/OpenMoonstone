use specs::{storage::BTreeStorage, Component, Entity, FlaggedStorage};

#[derive(Debug)]
pub struct Interactable {
    pub target: Entity,
}

impl Component for Interactable {
    type Storage = FlaggedStorage<Self, BTreeStorage<Self>>;
}
