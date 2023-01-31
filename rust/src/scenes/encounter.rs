use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    path,
};

use color_eyre::eyre::{eyre, Result, WrapErr};
use ggez::{
    glam::Vec2,
    graphics::{self, Canvas},
};

use crate::{
    assets, files,
    files::terrain::{Background, SCENERY_RECTS},
    game, input, piv, scenes, scenestack,
};

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

    pub fn build(
        &self,
        ctx: &mut ggez::Context,
        assets: &mut assets::Assets,
    ) -> Result<EncounterScene> {
        let background = assets.piv.get(self.background).ok_or_else(|| {
            eyre!(format!(
                "{} has not been loaded as a piv asset",
                self.background
            ))
        })?;

        let background_image = graphics::Image::from_pixels(
            ctx,
            &background.to_rgba8(),
            graphics::ImageFormat::Rgba8UnormSrgb,
            320,
            200,
        );

        // Manually create frame in order to use render passes outside of draw
        // This allows us to draw the background once and reuse that image
        // in each frame
        //
        // https://github.com/ggez/ggez/issues/1056
        ctx.gfx.begin_frame()?;

        let canvas_image = graphics::Image::new_canvas_image(
            ctx,
            graphics::ImageFormat::Rgba8UnormSrgb,
            320,
            200,
            1,
        );
        let mut canvas = Canvas::from_image(ctx, canvas_image.clone(), Option::None);
        // Draw the basic background
        canvas.draw(&background_image, graphics::DrawParam::default());

        // Draw scenery from terrain tileset
        let scenery = assets.terrain.get(self.terrain).ok_or_else(|| {
            eyre!(format!(
                "{} has not been loaded as a terrain asset",
                self.terrain
            ))
        })?;

        for p in &scenery.positions {
            let cmp = assets.piv.get(&p.atlas).ok_or_else(|| {
                eyre!(format!(
                    "Failed to load terrain sprite sheet {} has not been loaded as a piv asset",
                    p.atlas
                ))
            })?;
            let entry = format!("{}-{}", p.atlas, scenery.background);

            let ggez_image = match assets.images.entry(entry) {
                Occupied(i) => i.into_mut(),
                Vacant(i) => i.insert(graphics::Image::from_pixels(
                    ctx,
                    &cmp.to_rgba8_512(),
                    graphics::ImageFormat::Rgba8UnormSrgb,
                    512u32,
                    512u32,
                )),
            };
            let rect = SCENERY_RECTS[p.image_number];
            let draw_params = graphics::DrawParam::default()
                .src(graphics::Rect {
                    x: rect.x as f32 / 512.0,
                    y: rect.y as f32 / 512.0,
                    w: rect.w as f32 / 512.0,
                    h: rect.h as f32 / 512.0,
                })
                .dest(Vec2::new(p.x as f32, p.y as f32));
            canvas.draw(ggez_image, draw_params);
        }
        canvas
            .finish(ctx)
            .wrap_err("Failed to draw encounter background")?;
        ctx.gfx.end_frame()?;

        Ok(EncounterScene {
            background: canvas_image,
        })
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
        let mut canvas = Canvas::from_frame(ctx, Option::None);
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
