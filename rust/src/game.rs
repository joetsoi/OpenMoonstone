use std::collections::HashMap;

use failure::Error;
use ggez::graphics;
use ggez::Context;
use warmy::{Store, StoreOpt};

use crate::input;

pub struct Game {
    pub gore_on: bool,
    pub input: input::InputState,
    pub store: Store<Context>,
    pub images: HashMap<String, graphics::Image>,
}

impl Game {
    pub fn new() -> Result<Game, Error> {
        Ok(Game {
            gore_on: true,
            input: input::InputState::new(),
            images: HashMap::new(),
            store: Store::new(StoreOpt::default())?,
        })
    }
}
