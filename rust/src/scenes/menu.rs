use std::time::Duration;

use failure::Error;
use ggez::{graphics, timer, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use warmy::{LogicalKey, Store};

use crate::game::Game;
use crate::input::{Button, InputEvent};
use crate::piv::PivImage;
use crate::scenes::FSceneSwitch;
use crate::text::Screen;

pub struct Menu {
    background: graphics::Image,
    done: bool,
}

impl Menu {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>) -> Result<Self, Error> {
        let piv = store.get::<_, PivImage>(&LogicalKey::new("ch"), ctx)?;
        let background = graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8())?;
        let menu_yaml = store.get::<_, Screen>(&warmy::LogicalKey::new("/menu.yaml"), ctx)?;
        Ok(Self {
            done: false,
            background,
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
