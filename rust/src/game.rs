use std::collections::{HashMap, HashSet};

use failure::Error;
use ggez::conf::NumSamples;
use ggez::graphics;
use ggez::Context;
use specs::World;
use warmy::{LogicalKey, Store, StoreOpt};

use crate::animation::{Frame, Sprite, SpriteData};
use crate::combat::components::{
    AnimationState, Body, Collided, Controller, Draw, Health, Intent, Position, State, Velocity,
    WalkingState, Weapon,
};
use crate::input;
use crate::manager::GameYaml;
use crate::objects::TextureAtlas;
use crate::piv::PivImage;
use crate::rect::Rect;

pub struct Game {
    pub input: input::InputState,
    pub store: Store<Context>,
    pub images: HashMap<String, graphics::Image>,
}

impl Game {
    pub fn new(ctx: &mut Context) -> Result<Game, Error> {
        let mut store: Store<Context> = Store::new(StoreOpt::default())?;

        Ok(Game {
            input: input::InputState::new(),
            images: HashMap::new(),
            store,
        })
    }
}
