use specs::VecStorage;
use specs_derive::*;

use super::intent::{AttackType, DefendType, XAxis, YAxis};
use super::Facing;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Action {
    Idle,
    Move { x: XAxis, y: YAxis },
    Attack(AttackType),
    AttackRecovery,
    Defend(DefendType),
    Hit { name: String },
    Death { name: String },
}

impl Action {
    pub fn is_attack(&self) -> bool {
        if let Action::Attack(..) = self {
            true
        } else {
            false
        }
    }
}

impl Default for Action {
    fn default() -> Action {
        Action::Idle
    }
}

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct State {
    pub action: Action,
    pub direction: Facing,
    pub length: u32,
    pub ticks: u32,
}
