use ggez::Context;

use crate::assets;
use crate::input;

pub struct Game {
    pub input: input::InputState,
    pub assets: assets::Assets,
}

impl Game {
    pub fn new(ctx: &mut Context) -> Game {
        Game {
            input: input::InputState::new(),
            assets: assets::Assets::new(ctx),
        }
    }
}
