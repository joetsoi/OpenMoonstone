use std::collections::hash_map::DefaultHasher;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::hash::{Hash, Hasher};
use std::iter::repeat;

use failure::Error;
use ggez::{graphics, Context, GameResult};
use warmy::{LogicalKey, Store};

use crate::game::Game;
use crate::objects::TextureAtlas;
use crate::palette::PaletteSwaps;
use crate::piv::{extract_palette, Colour, PivImage};
use crate::text::Screen;

#[derive(Debug)]
pub struct Menu {
    pub screen: Screen,
    background: Option<graphics::Image>,
    pub palette: Vec<Colour>,
    pub palette_hash: u64,
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

impl Menu {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>, key: &str) -> Result<Self, Error> {
        let screen = store
            .get::<_, Screen>(&warmy::LogicalKey::new(key), ctx)?
            .borrow()
            .clone();

        let (background, palette) = match &screen.background {
            Some(background) => {
                let piv = store.get::<_, PivImage>(&LogicalKey::new(background), ctx)?;
                let mut palette = piv.borrow().palette.to_vec();
                if palette.len() == 16 {
                    palette.extend(
                        repeat(Colour {
                            r: 0,
                            g: 0,
                            b: 0,
                            a: 0,
                        })
                        .take(16),
                    );
                }
                let image = graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8())?;
                (Some(image), palette)
            }
            None => {
                let swaps_res = store
                    .get::<_, PaletteSwaps>(&LogicalKey::new("/palettes.yaml"), ctx)
                    .expect("error loading palette.yaml");
                let swaps = swaps_res.borrow();
                let raw_palette = swaps
                    .0
                    .get("default")
                    .expect("failed to fetch default palette");
                let palette = extract_palette(raw_palette);
                (None, palette)
            }
        };

        let palette_hash = calculate_hash(&palette);
        Ok(Self {
            background,
            palette,
            screen,
            palette_hash,
        })
    }

    pub fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        if let Some(background) = &self.background {
            graphics::draw_ex(
                ctx,
                background,
                graphics::DrawParam {
                    dest: graphics::Point2::new(0.0, 0.0),
                    scale: graphics::Point2::new(3.0, 3.0),
                    ..Default::default()
                },
            )?;
        }

        for text in &self.screen.text {
            let palette_name = self.screen.background.as_ref();
            let mut batch: graphics::spritebatch::SpriteBatch = text
                .as_sprite_batch(ctx, game, &self.palette, self.palette_hash)
                .expect("error drawing text to screen");
            graphics::draw_ex(
                ctx,
                &batch,
                graphics::DrawParam {
                    dest: graphics::Point2::new(0.0, 0.0),
                    scale: graphics::Point2::new(3.0, 3.0),
                    ..Default::default()
                },
            )?;
            batch.clear();
        }

        for image in &self.screen.images {
            let atlas = game
                .store
                .get::<_, TextureAtlas>(&LogicalKey::new(image.sheet.as_str()), ctx)
                .unwrap();

            let atlas_dimension = atlas.borrow().image.width as u32;
            let image_name = format!("{}{}", image.sheet, self.palette_hash);
            let ggez_image = match game.images.entry(image_name) {
                Occupied(i) => i.into_mut(),
                Vacant(i) => i.insert(graphics::Image::from_rgba8(
                    ctx,
                    atlas_dimension as u16,
                    atlas_dimension as u16,
                    &atlas.borrow().image.to_rgba8(&self.palette),
                )?),
            };

            let rect = atlas.borrow().rects[image.image];
            let texture_size = atlas.borrow().image.width as f32;
            let draw_params = graphics::DrawParam {
                src: graphics::Rect {
                    x: rect.x as f32 / texture_size,
                    y: rect.y as f32 / texture_size,
                    w: rect.w as f32 / texture_size,
                    h: rect.h as f32 / texture_size,
                },
                dest: graphics::Point2::new(image.x as f32 * 3.0, image.y as f32 * 3.0),
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            };
            graphics::draw_ex(ctx, ggez_image, draw_params)?;
        }
        Ok(())
    }
}
