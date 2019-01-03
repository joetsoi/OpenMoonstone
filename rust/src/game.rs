use std::collections::HashMap;

use failure::Error;
use ggez::graphics;
use ggez::Context;
use warmy::{Store, StoreOpt};

use crate::input;

pub enum SceneState {
    Menu,
    Practice,
}

pub struct Game {
    pub input: input::InputState,
    pub store: Store<Context>,
    pub images: HashMap<String, graphics::Image>,

    pub scene: SceneState,
    pub next_scene: SceneState,

    pub gore_on: bool,
    pub num_players: i32,
}

impl Game {
    pub fn new() -> Result<Game, Error> {
        Ok(Game {
            input: input::InputState::new(),
            images: HashMap::new(),
            store: Store::new(StoreOpt::default())?,
            
            scene: SceneState::Menu,
            next_scene: SceneState::Practice,

            gore_on: true,
            num_players: 1,
        })
    }
}
