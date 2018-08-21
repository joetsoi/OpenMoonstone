use specs::VecStorage;
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
pub enum Command {
    Idle,
    Move { x: XAxis, y: YAxis },
    Attack,
    Defend,
}

impl Default for Command {
    fn default() -> Command {
        Command::Idle
    }
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Intent {
    pub command: Command,
}
