use std::collections::hash_map::Entry::{Occupied, Vacant};

use failure::{err_msg, Error};
use ggez::event;
use ggez::input::keyboard::KeyCode;
use ggez::nalgebra::{Point2, Vector2};
use ggez::{graphics, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use warmy::{LogicalKey, Store};

use crate::game::{Game, SceneState};
use crate::input::{Axis, Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::palette::PaletteSwaps;
use crate::piv::{extract_palette, Colour};
use crate::scenes::FSceneSwitch;
use crate::text::Text;

use super::menu::Menu;

enum State {
    Selecting,
    Naming,
}

pub struct SelectKnight {
    menu: Menu,
    oscillate: ColourOscillate,
    swap_colour: Colour,

    state: State,

    current: usize,
    selected: Vec<u32>,
    available: Vec<u32>,

    current_name: String,
}

struct ColourOscillate {
    from: Colour,
    to: Colour,
    current: Colour,
    target: Colour,
}

impl ColourOscillate {
    pub fn new(from: Colour, to: Colour) -> Self {
        ColourOscillate {
            from: from.clone(),
            to: to.clone(),
            current: from.clone(),
            target: to.clone(),
        }
    }
}

impl Iterator for ColourOscillate {
    type Item = Colour;

    fn next(&mut self) -> Option<Self::Item> {
        if self.target.r > self.current.r {
            self.current.r += 16
        } else if self.target.r < self.current.r {
            self.current.r -= 16
        };

        if self.target.g > self.current.g {
            self.current.g += 16
        } else if self.target.g < self.current.g {
            self.current.g -= 16
        };

        if self.target.b > self.current.b {
            self.current.b += 16
        } else if self.target.b < self.current.b {
            self.current.b -= 16
        };

        if self.current == self.target {
            if self.target == self.from {
                self.target = self.to
            } else {
                self.target = self.from
            }
        }
        Some(self.current.clone())
    }
}

impl SelectKnight {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>) -> Result<Self, Error> {
        let menu = Menu::new(ctx, store, "/select_knight.yaml")?;

        let swaps_res = store.get::<_, PaletteSwaps>(&LogicalKey::new("/palettes.yaml"), ctx)?;
        let swaps = swaps_res.borrow();
        let raw_palette = swaps
            .0
            .get("select_knight")
            .ok_or_else(|| err_msg("failed to load select_knight.yaml"))?;
        let mut swap_colour = extract_palette(raw_palette)
            .first()
            .ok_or_else(|| err_msg("select_knight palette does not have a colour defined"))?
            .clone();
        swap_colour.a = 255;

        let original_colour = menu.palette[15].clone();

        let oscillate = ColourOscillate::new(original_colour, swap_colour);

        Ok(Self {
            menu,
            oscillate,
            swap_colour: original_colour.clone(),
            state: State::Selecting,
            current: 0,
            available: vec![0, 1, 2, 3],
            selected: Vec::new(),
            current_name: String::from("SIR GODBER"),
        })
    }

    fn draw_cursor(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        let atlas = game
            .store
            .get::<_, TextureAtlas>(&LogicalKey::new(&self.menu.screen.cursor.sheet), ctx)
            // TODO: raise error
            .expect("Couldn't find sel.cel yaml metadata");

        let ggez_image = match game.images.entry(format!(
            "{}-{}-{}-{}",
            self.menu.screen.cursor.sheet,
            self.swap_colour.r,
            self.swap_colour.g,
            self.swap_colour.b
        )) {
            Occupied(i) => i.into_mut(),
            Vacant(i) => {
                let mut palette = self.menu.palette.clone();
                palette[15] = self.swap_colour;

                let atlas_dimension = atlas.borrow().image.width as u32;
                i.insert(graphics::Image::from_rgba8(
                    ctx,
                    atlas_dimension as u16,
                    atlas_dimension as u16,
                    &atlas.borrow().image.to_rgba8(&palette),
                )?)
            }
        };

        let rect = atlas.borrow().rects[self.menu.screen.cursor.image];
        let texture_size = atlas.borrow().image.width as f32;
        let draw_params = graphics::DrawParam::default()
            .src(graphics::Rect {
                x: rect.x as f32 / texture_size,
                y: rect.y as f32 / texture_size,
                w: rect.w as f32 / texture_size,
                h: rect.h as f32 / texture_size,
            })
            .dest(Point2::new(
                self.menu.screen.cursor.x as f32 * 3.0,
                self.menu.screen.cursor.y as f32 * 3.0,
            ))
            .scale(Vector2::new(3.0, 3.0));
        graphics::draw(ctx, ggez_image, draw_params)?;

        Ok(())
    }

    fn select_current_knight(&mut self) {
        self.selected.push(self.available.remove(self.current));
        self.menu.screen.images.remove(self.current);
        self.state = State::Naming;

        self.current = 0;
    }
}

impl Scene<Game, InputEvent> for SelectKnight {
    fn update(&mut self, game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        if let Some(colour) = self.oscillate.next() {
            self.swap_colour = colour;
        }
        self.menu.screen.cursor.x = self
            .menu
            .screen
            .images
            .iter()
            .map(|i| i.x)
            .nth(self.current)
            .unwrap_or_else(|| self.menu.screen.cursor.x);

        if self.selected.len() == game.num_players as usize {
            SceneSwitch::Pop
        } else {
            SceneSwitch::None
        }
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        graphics::clear(ctx, graphics::Color::from((0, 0, 0, 255)));
        self.menu.draw(game, ctx);
        match self.state {
            State::Selecting => self.draw_cursor(game, ctx)?,
            State::Naming => {
                let mut name_input = self.current_name.clone();
                name_input.push('/');
                let text = Text {
                    string: name_input,
                    font: "bold.f".to_string(),
                    bordered: true,
                    centered: false,
                    x: 50,
                    y: 50,
                };
                let spritebatch = text
                    .as_sprite_batch(ctx, game, &self.menu.palette, self.menu.palette_hash)
                    .expect("fix this sprite batch");
                let draw_params = graphics::DrawParam::default().scale(Vector2::new(3.0, 3.0));
                graphics::draw(ctx, &spritebatch, draw_params)?;
            }
        };
        Ok(())
    }

    fn name(&self) -> &str {
        "Select a Knight"
    }

    fn input(&mut self, gameworld: &mut Game, event: InputEvent, started: bool) {
        match self.state {
            State::Selecting => {
                let x = gameworld.input.get_axis_raw(Axis::Horz1) as i32;
                let len = self.available.len() as i32;
                if x > 0 {
                    self.current = ((self.current as i32 + x) % len) as usize;
                } else {
                    self.current = ((self.current as i32 + x + len) % len) as usize;
                }

                if gameworld.input.get_button_down(Button::Fire1) {
                    self.select_current_knight();
                }
            }
            State::Naming => match event {
                InputEvent::Text(c) => {
                    if c.is_alphanumeric() || c.is_ascii_whitespace() {
                        self.current_name.push(c.to_ascii_uppercase());
                    }
                }
                InputEvent::Key(keycode) => {
                    if keycode == KeyCode::Back {
                        self.current_name.pop();
                    }
                }
                _ => (),
            },
        }
    }
}
