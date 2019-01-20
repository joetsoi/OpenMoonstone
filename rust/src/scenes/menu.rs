use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::iter::repeat;

use failure::Error;
use ggez::{graphics, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use lazy_static::lazy_static;
use warmy::{LogicalKey, Store};

use super::transition::FadeStyle;
use super::Fade;
use crate::game::{Game, SceneState};
use crate::input::{Axis, Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::palette::PaletteSwaps;
use crate::piv::Colour;
use crate::piv::{extract_palette, PivImage};
use crate::scenes::FSceneSwitch;
use crate::text::{Screen, Text};

struct MenuImage {
    sheet: &'static str,
    image: usize,
    x: u32,
    y: u32,
}

const ARROW: MenuImage = MenuImage {
    sheet: "sel.cel",
    image: 0,
    x: 50,
    y: 85,
};

const ARROW_POSITIONS: [u32; 4] = [85, 110, 152, 172];

lazy_static! {
    static ref ON: Text = Text {
        string: "On".to_string(),
        font: "bold.f".to_string(),
        bordered: true,
        centered: false,
        x: 214,
        y: 108,
    };
    static ref OFF: Text = Text {
        string: "Off".to_string(),
        font: "bold.f".to_string(),
        bordered: true,
        centered: false,
        x: 214,
        y: 108,
    };
    static ref PLAYER_COUNT: Text = Text {
        string: "1".to_string(),
        font: "bold.f".to_string(),
        bordered: true,
        centered: false,
        x: 214,
        y: 83,
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum MenuOption {
    Players = 0,
    Gore = 1,
    Practice = 2,
    SelectKnight = 3,
}

impl MenuOption {
    fn from_i32(n: i32) -> MenuOption {
        match n {
            0 => MenuOption::Players,
            1 => MenuOption::Gore,
            2 => MenuOption::Practice,
            3 => MenuOption::SelectKnight,
            _ => panic!("Something went really wrong selecting menu options"),
        }
    }
}

#[derive(Debug)]
pub struct Menu {
    background: graphics::Image,
    palette: Vec<Colour>,
    done: bool,
    fade_out_done: bool,
    screen: Screen,
    selected_option: MenuOption,
}

impl Menu {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>) -> Result<Self, Error> {
        let screen = store
            .get::<_, Screen>(&warmy::LogicalKey::new("/menu.yaml"), ctx)?
            .borrow()
            .clone();

        let (background, palette) = match &screen.background {
            Some(background) => {
                let piv = store.get::<_, PivImage>(&LogicalKey::new(background), ctx)?;
                let mut palette = piv.borrow().palette.to_vec();
                palette.extend(
                    repeat(Colour {
                        r: 0,
                        g: 0,
                        b: 0,
                        a: 0,
                    })
                    .take(16),
                );
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
        Ok(Self {
            background: background
                .unwrap_or_else(|| panic!("error in menu.yaml, must have 'background")),
            done: false,
            fade_out_done: false,
            palette,
            screen,
            selected_option: MenuOption::Players,
        })
    }
}

impl Menu {
    fn draw_screen(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        graphics::draw_ex(
            ctx,
            &self.background,
            graphics::DrawParam {
                dest: graphics::Point2::new(0.0, 0.0),
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;

        for text in &self.screen.text {
            let mut batch: graphics::spritebatch::SpriteBatch = text
                .as_sprite_batch(ctx, game, &self.palette)
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
            let ggez_image = match game.images.entry(image.sheet.clone()) {
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

    fn draw_arrow(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        // we don't want to save this image to the game cache as we only
        // want to apply the pallete to the the arrow. We've extended the palette
        // by 16 empty colours so to_rgba8 won't break.
        let atlas = game
            .store
            .get::<_, TextureAtlas>(&LogicalKey::new(ARROW.sheet), ctx)
            // TODO: raise error
            .expect("Couldn't find sel.cel yaml metadata");

        let atlas_dimension = atlas.borrow().image.width as u32;
        let arrow_image = graphics::Image::from_rgba8(
            ctx,
            atlas_dimension as u16,
            atlas_dimension as u16,
            &atlas.borrow().image.to_rgba8(&self.palette),
        )?;
        let rect = atlas.borrow().rects[ARROW.image];
        let texture_size = atlas.borrow().image.width as f32;
        let y = ARROW_POSITIONS[self.selected_option as usize];
        let draw_params = graphics::DrawParam {
            src: graphics::Rect {
                x: rect.x as f32 / texture_size,
                y: rect.y as f32 / texture_size,
                w: rect.w as f32 / texture_size,
                h: rect.h as f32 / texture_size,
            },
            dest: graphics::Point2::new(ARROW.x as f32 * 3.0, y as f32 * 3.0),
            scale: graphics::Point2::new(3.0, 3.0),
            ..Default::default()
        };
        graphics::draw_ex(ctx, &arrow_image, draw_params)?;
        Ok(())
    }

    fn draw_gore_option(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        let mut batch = if game.gore_on {
            ON.as_sprite_batch(ctx, game, &self.palette)
                .expect("error drawing ON")
        } else {
            OFF.as_sprite_batch(ctx, game, &self.palette)
                .expect("error drawing OFF")
        };

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
        Ok(())
    }

    fn draw_player_count_option(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        let mut text = PLAYER_COUNT.clone();
        text.string = game.num_players.to_string();
        let mut batch = text
            .as_sprite_batch(ctx, game, &self.palette)
            .expect("error drawing PLAYER_COUNT");
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
        Ok(())
    }
}

impl Scene<Game, InputEvent> for Menu {
    fn update(&mut self, _game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        if self.done {
            if !self.fade_out_done {
                SceneSwitch::push(Fade::new(274, 1, FadeStyle::Out))
            } else {
                SceneSwitch::Pop // shouldn't happen
            }
        } else {
            SceneSwitch::None
        }
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        graphics::set_background_color(ctx, graphics::Color::from((0, 0, 0, 255)));
        graphics::clear(ctx);
        self.draw_screen(game, ctx)?;
        self.draw_arrow(game, ctx)?;
        self.draw_gore_option(game, ctx)?;
        self.draw_player_count_option(game, ctx)?;
        Ok(())
    }

    fn name(&self) -> &str {
        "Main menu"
    }

    fn input(&mut self, gameworld: &mut Game, _event: InputEvent, started: bool) {
        let x = gameworld.input.get_axis_raw(Axis::Horz1) as i32;
        if gameworld.input.get_button_down(Button::Fire1) {
            match self.selected_option {
                MenuOption::Practice => {
                    self.done = true;
                    gameworld.next_scene = SceneState::Practice;
                }
                MenuOption::Gore => gameworld.gore_on = !gameworld.gore_on,
                MenuOption::Players => gameworld.num_players = (gameworld.num_players % 4) + 1,
                _ => (),
            }
        } else if x != 0 {
            match self.selected_option {
                MenuOption::Gore => gameworld.gore_on = !gameworld.gore_on,
                MenuOption::Players => {
                    if x > 0 {
                        gameworld.num_players = (gameworld.num_players % 4) + x;
                    } else {
                        gameworld.num_players = (gameworld.num_players + 3 + x) % 4 + 1;
                    }
                }
                _ => (),
            }
        }

        if !started {
            let y = gameworld.input.get_axis_raw(Axis::Vert1) as i32;
            if y > 0 {
                self.selected_option = MenuOption::from_i32((self.selected_option as i32 + y) % 4);
            } else if y < 0 {
                self.selected_option =
                    MenuOption::from_i32((self.selected_option as i32 + 4 + y) % 4);
            }
        }
    }
}
