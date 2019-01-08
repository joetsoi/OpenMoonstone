use std::collections::HashMap;

use failure::Error;
use ggez::graphics;
use ggez::Context;
use warmy::{Store, StoreOpt};

use crate::input;

#[derive(Debug)]
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

    pub encounter_starting_position: u32,
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
            encounter_starting_position: 0,
        })
    }
}
