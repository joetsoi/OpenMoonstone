use specs::{NullStorage, VecStorage};
use specs_derive::*;

#[derive(Component, Debug)]
#[storage(VecStorage)]
pub struct Health {
    pub points: i32,
    pub max: i32,
}

impl Default for Health {
    fn default() -> Health {
        Health {
            points: 10,
            max: 10,
        }
    }
}

/// Combat ends anytime the health of an entity that must live drops below 0.
#[derive(Component, Default)]
#[storage(NullStorage)]
pub struct MustLive;
