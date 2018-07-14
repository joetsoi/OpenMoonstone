use std::sync::Arc;

use ggez::graphics::spritebatch::SpriteBatch;
use specs::{Component, VecStorage};
use specs_derive::*;

#[derive(Debug)]
pub struct Draw {
    pub sprite_sheet: Arc<SpriteBatch>,
    pub rects: Vec<u32>,
}

impl Component for Draw  {
    type Storage = VecStorage<Self>;
}

