use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::path;

use ggez::graphics;

use crate::assets;
use crate::files;
use crate::game;
use crate::input;
use crate::piv;
use crate::scenes;
use crate::scenestack;

pub struct EncounterBuilder {
    pub background: &'static str,
    pub terrain: &'static str,
}

impl EncounterBuilder {
    pub fn new(background: &'static str, terrain: &'static str) -> Self {
        Self {
            background,
            terrain,
        }
    }

    pub fn build(&self, ctx: &mut ggez::Context, assets: &mut assets::Assets) -> EncounterScene {
        let background = assets.piv.get(self.background).unwrap();

        let background_image = graphics::Image::from_pixels(
            ctx,
            &background.to_rgba8(),
            graphics::ImageFormat::Rgba8UnormSrgb,
            320,
            200,
        );

        let scenery = assets.terrain.get(self.terrain).unwrap();
        // for p in &scenery.positions {
        //     dbg!(p);
        // }

        EncounterScene {
            background: background_image,
        }
    }
}

pub struct EncounterScene {
    pub background: graphics::Image,
}

impl scenestack::Scene<game::Game, input::InputEvent> for EncounterScene {
    fn update(&mut self, _game: &mut game::Game, _ctx: &mut ggez::Context) -> scenes::FSceneSwitch {
        return scenestack::SceneSwitch::None;
    }

    fn draw(&mut self, _game: &mut game::Game, ctx: &mut ggez::Context) -> ggez::GameResult<()> {
        let mut canvas = graphics::Canvas::from_frame(ctx, Option::None);
        canvas.set_sampler(graphics::Sampler::nearest_clamp());
        canvas.set_screen_coordinates(graphics::Rect::new(0., 0., 320., 200.));
        canvas.draw(&self.background, graphics::DrawParam::default());
        canvas.finish(ctx)?;
        Ok(())
    }

    fn name(&self) -> &str {
        "Encounter"
    }

    fn input(&mut self, _game: &mut game::Game, _event: input::InputEvent, _started: bool) {}
}
