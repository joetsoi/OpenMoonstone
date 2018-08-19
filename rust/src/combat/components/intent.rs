use specs::VecStorage;
use specs_derive::*;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum MoveCommand {
    TryMoveUp,
    TryMoveDown,
    TryMoveLeft,
    TryMoveRight,
    TryMoveLeftUp,
    TryMoveRightUp,
    TryMoveLeftDown,
    TryMoveRightDown,
}

#[derive(Debug, Copy, Clone)]
pub enum Command {
    Idle,
    Move(MoveCommand),
    TrySwing,
}

impl Default for Command {
    fn default() -> Command { Command::Idle }
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct Intent {
    pub command: Command,
}
