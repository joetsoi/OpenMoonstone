use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum XAxis {
    Left = -1,
    Centre = 0,
    Right = 1,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum YAxis {
    Up = -1,
    Centre = 0,
    Down = 1,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum MapCommand {
    Idle,
    Move { x: XAxis, y: YAxis },
    Interact,
}

impl Default for MapCommand {
    fn default() -> MapCommand {
        MapCommand::Idle
    }
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct MapIntent {
    pub command: MapCommand,
}
