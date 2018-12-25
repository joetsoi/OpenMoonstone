use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;

use failure;
use failure_derive::Fail;
use ggez::graphics;
use ggez::graphics::spritebatch::SpriteBatch;
use ggez::Context;
use lazy_static::lazy_static;
use maplit::hashmap;
use serde_derive::{Deserialize, Serialize};
use serde_yaml::Value;
use warmy::{LogicalKey, Store};

use crate::error::{err_from, CompatError};
use crate::game::Game;
use crate::objects::TextureAtlas;
use crate::piv::Colour;

#[derive(Debug, Fail)]
pub enum InvalidFont {
    #[fail(display = "font {} not in font_lookup", font)]
    FontDoesNotExist { font: String },
    #[fail(display = "image {} not in font", num)]
    ImageDoesNotExist { num: usize },
}

lazy_static! {
    static ref font_lookup: HashMap<&'static str, Vec<usize>> = hashmap! {
        "bold.f" => vec![
            69, 62, 69, 66, 67, 68, 69, 70, 69, 69,
            69, 69, 65, 69, 64, 71, 52, 53, 54, 55,
            56, 57, 58, 59, 60, 61, 69, 69, 69, 69,
            69, 69, 69, 0, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 69,
            71, 69, 69, 69, 69, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
            51, 69, 69, 69, 69, 48
        ],
    };
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Screen {
    pub background: String,
    pub text: Vec<Text>,
    pub images: Vec<Image>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Text {
    string: String,
    font: String,
    bordered: bool,
    centered: bool,
    x: u32,
    y: u32,
}

impl Text {
    pub fn as_draw_params(
        &self,
        ctx: &mut Context,
        store: &mut Store<Context>,
    ) -> Result<Vec<graphics::DrawParam>, failure::Error> {
        let lookup: &Vec<usize> =
            font_lookup
                .get(self.font.as_str())
                .ok_or_else(|| InvalidFont::FontDoesNotExist {
                    font: self.font.clone(),
                })?;
        let atlas = store
            .get::<_, TextureAtlas>(&LogicalKey::new(self.font.as_str()), ctx)
            .map_err(err_from)?;

        let mut lookup_width: Vec<(usize, u32)> = Vec::new();
        let mut string_width: u32 = 0;
        for c in self.string.chars() {
            let num: usize = c as usize - 0x20;
            let image_num = lookup
                .get(num)
                .ok_or_else(|| InvalidFont::ImageDoesNotExist { num })?;
            let mut visible_width = atlas.borrow().visible_widths[*image_num];
            if self.bordered {
                visible_width -= 3;
            }
            string_width += visible_width;
            lookup_width.push((*image_num, visible_width));
        }

        let mut params: Vec<graphics::DrawParam> = Vec::new();
        let mut x = self.x as f32;
        if self.centered {
            // TODO: change to pass width in
            x = (320 - string_width) as f32 / 2.0;
        }
        for (i, w) in lookup_width.iter() {
            // let num: usize = c as usize - 0x20;
            // let image_num = lookup
            //     .get(num)
            //     .ok_or_else(|| InvalidFont::ImageDoesNotExist { num })?;

            let rect = atlas.borrow().rects[*i];
            let texture_size = atlas.borrow().image.width as f32;
            params.push(graphics::DrawParam {
                src: graphics::Rect {
                    x: rect.x as f32 / texture_size,
                    y: rect.y as f32 / texture_size,
                    w: rect.w as f32 / texture_size,
                    h: rect.h as f32 / texture_size,
                },
                dest: graphics::Point2::new(x as f32, self.y as f32),
                ..Default::default()
            });
            x += *w as f32;
        }
        Ok(params)
    }

    pub fn as_sprite_batch(
        &self,
        ctx: &mut Context,
        game: &mut Game,
        palette: &Vec<Colour>,
    ) -> Result<SpriteBatch, failure::Error> {
        let atlas = game
            .store
            .get::<_, TextureAtlas>(&LogicalKey::new(self.font.as_str()), ctx)?;

        let atlas_dimension = atlas.borrow().image.width as u32;
        let ggez_image = match game.images.entry(self.font.clone()) {
            Occupied(i) => i.into_mut(),
            Vacant(i) => i.insert(graphics::Image::from_rgba8(
                ctx,
                atlas_dimension as u16,
                atlas_dimension as u16,
                &atlas.borrow().image.to_rgba8(palette),
            )?),
        };
        let mut batch = SpriteBatch::new(ggez_image.clone());
        let params = self.as_draw_params(ctx, &mut game.store)?;
        for p in params {
            batch.add(p);
        }
        Ok(batch)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Image {
    pub sheet: String,
    pub image: usize,
    pub x: i32,
    pub y: i32,
}

impl warmy::Load<Context> for Screen {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        _store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;
        let screen: Screen = serde_yaml::from_value(yaml).map_err(err_from)?;
        Ok(warmy::Loaded::from(screen))
    }
}
