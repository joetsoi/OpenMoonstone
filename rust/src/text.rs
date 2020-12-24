use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use ggez::graphics::spritebatch::SpriteBatch;
use ggez::nalgebra::Point2;
use ggez::{graphics, Context};
use lazy_static::lazy_static;
use maplit::hashmap;
use serde_derive::{Deserialize, Serialize};
use warmy::{SimpleKey, Store};

use loadable_macro_derive::{LoadableRon, LoadableYaml};

use crate::game::Game;
use crate::objects::TextureAtlas;
use crate::piv::Colour;
use crate::ron::FromDosFilesRon;

#[derive(Debug)]
pub enum InvalidFont {
    FontDoesNotExist { font: String },
    ImageDoesNotExist { num: usize },
}

impl Error for InvalidFont {}

impl fmt::Display for InvalidFont {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InvalidFont::FontDoesNotExist { ref font } => {
                write!(f, "font {} not in FONT_LOOKUP", font)
            }
            InvalidFont::ImageDoesNotExist { num } => write!(f, "image {} not in font", num),
        }
    }
}

lazy_static! {
    static ref FONT_LOOKUP: HashMap<&'static str, Vec<usize>> = hashmap! {
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
        "small.f" => vec![
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

#[derive(Debug, Default, Clone, Serialize, Deserialize, LoadableRon)]
pub struct Screen {
    pub background: Option<String>,
    pub text: Vec<Text>,
    pub images: Vec<Image>,
    pub cursor: Image,
}

impl fmt::Display for Screen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Screen {}",
            self.background.as_ref().unwrap_or(&format!("test"))
        )
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Text {
    pub string: String,
    pub font: String,
    pub bordered: bool,
    pub centered: bool,
    pub x: u32,
    pub y: u32,
}

impl Text {
    pub fn as_draw_params(
        &self,
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
    ) -> Result<Vec<graphics::DrawParam>, Box<dyn Error>> {
        let lookup: &Vec<usize> =
            FONT_LOOKUP
                .get(self.font.as_str())
                .ok_or_else(|| InvalidFont::FontDoesNotExist {
                    font: self.font.clone(),
                })?;
        let atlas = store
            .get::<TextureAtlas>(&SimpleKey::from(self.font.as_str()), ctx)
            //TODO: use error hadling ? syntax
            .expect("erro loading texture atlas in Text.as_draw_params");

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
        let mut x = if self.centered {
            (320 - string_width) as f32 / 2.0
        } else {
            self.x as f32
        };
        // let mut x = self.x as f32;
        // if self.centered {
        //     // TODO: change to pass width in
        //     x = (320 - string_width) as f32 / 2.0;
        // }
        for (i, w) in lookup_width.iter() {
            // let num: usize = c as usize - 0x20;
            // let image_num = lookup
            //     .get(num)
            //     .ok_or_else(|| InvalidFont::ImageDoesNotExist { num })?;

            let rect = atlas.borrow().rects[*i];
            let texture_size = atlas.borrow().image.width as f32;
            params.push(
                graphics::DrawParam::default()
                    .src(graphics::Rect {
                        x: rect.x as f32 / texture_size,
                        y: rect.y as f32 / texture_size,
                        w: rect.w as f32 / texture_size,
                        h: rect.h as f32 / texture_size,
                    })
                    .dest(Point2::new(x as f32, self.y as f32)),
            );
            x += *w as f32;
        }
        Ok(params)
    }

    pub fn as_sprite_batch(
        &self,
        ctx: &mut Context,
        game: &mut Game,
        palette: &[Colour],
        palette_hash: u64,
    ) -> Result<SpriteBatch, Box<dyn Error>> {
        let atlas = game
            .store
            .get_by::<TextureAtlas, FromDosFilesRon>(
                &SimpleKey::from(self.font.as_str()),
                ctx,
                FromDosFilesRon,
            )
            //TODO: fix with ? syntax
            .expect(&format!(
                "error with textureatlas {} in as_sprite_batch",
                self.font
            ));

        let image_name = format!("{}{}", self.font, palette_hash);
        let atlas_dimension = atlas.borrow().image.width as u32;
        let ggez_image = match game.images.entry(image_name) {
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

// TODO: move this to its own module
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Image {
    pub sheet: String,
    pub image: usize,
    pub x: i32,
    pub y: i32,
}
