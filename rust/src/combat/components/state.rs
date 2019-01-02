use specs::VecStorage;
use specs_derive::*;

use super::intent::{AttackType, DefendType, XAxis, YAxis};
use super::Facing;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum HitType {
    Chopped,
    Sliced,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Action {
    Idle,
    Move { x: XAxis, y: YAxis },
    Attack(AttackType),
    AttackRecovery,
    Defend(DefendType),
    Hit(HitType),
    Death,
    Dead,
}

impl Action {
    pub fn is_attack(&self) -> bool {
        if let Action::Attack(..) = self {
            true
        } else {
            false
        }
    }

    pub fn is_throw_dagger(&self) -> bool {
        if let Action::Attack(AttackType::ThrowDagger) = self {
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
