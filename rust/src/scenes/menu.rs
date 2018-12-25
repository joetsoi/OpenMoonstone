use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::iter::repeat;
use std::time::Duration;

use failure::Error;
use ggez::{graphics, timer, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use warmy::{LogicalKey, Store};

use crate::error::{err_from, CompatError};
use crate::game::Game;
use crate::input::{Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::piv::Colour;
use crate::piv::PivImage;
use crate::scenes::FSceneSwitch;
use crate::text::Screen;

pub struct Menu {
    background: graphics::Image,
    palette: Vec<Colour>,
    done: bool,
    screen: Screen,
}

impl Menu {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>) -> Result<Self, Error> {
        let piv = store.get::<_, PivImage>(&LogicalKey::new("ch"), ctx)?;
        let background = graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8())?;
        let screen_res = store.get::<_, Screen>(&warmy::LogicalKey::new("/menu.yaml"), ctx)?;
        let screen = screen_res.borrow().clone();
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
        Ok(Self {
            done: false,
            background,
            palette,
            screen,
        })
    }
}

impl Scene<Game, InputEvent> for Menu {
    fn update(&mut self, game: &mut Game) -> FSceneSwitch {
        if self.done {
            SceneSwitch::Pop
        } else {
            SceneSwitch::None
        }
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        graphics::set_background_color(ctx, graphics::Color::from((0, 0, 0, 255)));
        graphics::clear(ctx);
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
                Vacant(i) => i.insert(
                    graphics::Image::from_rgba8(
                        ctx,
                        atlas_dimension as u16,
                        atlas_dimension as u16,
                        &atlas.borrow().image.to_rgba8(&self.palette),
                    )
                    .unwrap(),
                ),
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

        graphics::present(ctx);
        timer::sleep(Duration::from_millis(50));
        Ok(())
    }

    fn name(&self) -> &str {
        "Main menu"
    }

    fn input(&mut self, gameworld: &mut Game, _event: InputEvent, _started: bool) {
        if gameworld.input.get_button_pressed(Button::Fire1) {
            self.done = true;
        }
    }
}
