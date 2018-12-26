use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::iter::repeat;
use std::time::Duration;

use failure::Error;
use ggez::{graphics, timer, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use warmy::{LogicalKey, Store};

use crate::game::Game;
use crate::input::{Axis, Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::piv::Colour;
use crate::piv::PivImage;
use crate::scenes::FSceneSwitch;
use crate::text::Screen;

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
            _ => MenuOption::Players,
        }
    }
}

#[derive(Debug)]
pub struct Menu {
    background: graphics::Image,
    palette: Vec<Colour>,
    done: bool,
    num_players: i32,
    screen: Screen,
    selected_option: MenuOption,
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
            background,
            done: false,
            palette,
            num_players: 1,
            screen,
            selected_option: MenuOption::Players,
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

    fn input(&mut self, gameworld: &mut Game, _event: InputEvent, started: bool) {
        let x = gameworld.input.get_axis_raw(Axis::Horz1) as i32;
        if gameworld.input.get_button_down(Button::Fire1) {
            match self.selected_option {
                MenuOption::Practice => self.done = true,
                MenuOption::Gore => gameworld.gore_on = !gameworld.gore_on,
                MenuOption::Players => self.num_players = (self.num_players % 4) + 1,
                _ => (),
            }
        } else if x != 0 {
            match self.selected_option {
                MenuOption::Gore => gameworld.gore_on = !gameworld.gore_on,
                MenuOption::Players => {
                    if x > 0 {
                        self.num_players = (self.num_players % 4) + x;
                    } else {
                        self.num_players = (self.num_players + 3 + x) % 4 + 1;
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
