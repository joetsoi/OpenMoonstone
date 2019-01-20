use failure::Error;
use ggez::{graphics, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use lazy_static::lazy_static;
use warmy::{LogicalKey, Store};

use crate::game::{Game, SceneState};
use crate::input::{Axis, Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::scenes::FSceneSwitch;
use crate::text::Text;

use super::menu::Menu;
use super::transition::FadeStyle;
use super::Fade;

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
pub struct MainMenuScene {
    menu: Menu,
    done: bool,
    fade_out_done: bool,
    selected_option: MenuOption,
}

impl MainMenuScene {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>) -> Result<Self, Error> {
        let menu = Menu::new(ctx, store, "/menu.yaml")?;
        // .unwrap_or_else(|| panic!("error in menu.yaml, must have 'background")),
        Ok(Self {
            menu,
            done: false,
            fade_out_done: false,
            selected_option: MenuOption::Players,
        })
    }
}

impl MainMenuScene {
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
            &atlas.borrow().image.to_rgba8(&self.menu.palette),
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
            ON.as_sprite_batch(ctx, game, &self.menu.palette)
                .expect("error drawing ON")
        } else {
            OFF.as_sprite_batch(ctx, game, &self.menu.palette)
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
            .as_sprite_batch(ctx, game, &self.menu.palette)
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

impl Scene<Game, InputEvent> for MainMenuScene {
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
        self.menu.draw(game, ctx)?;
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
