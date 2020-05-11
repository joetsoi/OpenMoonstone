use std::collections::HashMap;

use ggez::graphics;
use ggez::nalgebra::Vector2;
use ggez::Context;
use warmy::{SimpleKey, Store, StoreOpt};

use crate::error::{LoadError, MoonstoneError};
use crate::input;

#[derive(Debug)]
pub enum SceneState {
    Menu,
    Practice,
}

pub struct Game {
    pub input: input::InputState,
    pub store: Store<Context, SimpleKey>,
    pub images: HashMap<String, graphics::Image>,

    pub scene: SceneState,
    pub next_scene: SceneState,

    pub gore_on: bool,
    pub num_players: i32,

    pub encounter_starting_position: u32,
    pub practice_encounter: u32,

    pub screen_scale: Vector2<f32>,
}

impl Game {
    pub fn new() -> Result<Game, MoonstoneError> {
        let store = Store::new(StoreOpt::default()).expect("error creating store");
        Ok(Game {
            input: input::InputState::new(),
            images: HashMap::new(),
            store: store,

            scene: SceneState::Menu,
            next_scene: SceneState::Practice,

            gore_on: true,
            num_players: 2,
            encounter_starting_position: 0,
            practice_encounter: 1,

            screen_scale: Vector2::new(2.0, 2.0),
        })
    }
}
