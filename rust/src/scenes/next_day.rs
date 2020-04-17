use ggez::{graphics, timer, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use warmy::{SimpleKey, Store};

use super::menu::Menu;
use super::transition::FadeStyle;
use super::Fade;

use crate::error::MoonstoneError;
use crate::game::Game;
use crate::input::{Axis, Button, InputEvent};
use crate::scenes::FSceneSwitch;

enum MoonPhase {
    Full,
}

pub struct NextDay {
    moon: MoonPhase,
    menu: Menu,
    done: bool,
}

impl NextDay {
    pub fn new(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>, //) -> Result<Self, Error> {
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let menu = Menu::new(ctx, store, "/next_day.yaml")?;
        Ok(NextDay {
            moon: MoonPhase::Full,
            menu: menu,
            done: false,
        })
    }
}

impl Scene<Game, InputEvent> for NextDay {
    fn update(&mut self, game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        match self.done {
            true => SceneSwitch::push(Fade::new(274, 1, FadeStyle::Out)),
            false =>SceneSwitch::None,
        }
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        graphics::clear(ctx, graphics::Color::from((0, 0, 0, 255)));
        self.menu.draw(game, ctx);
        Ok(())
    }

    fn name(&self) -> &str {
        "NextDay"
    }

    fn input(&mut self, gameworld: &mut Game, event: InputEvent, started: bool) {
        if gameworld.input.get_button_down(Button::Fire1) {
            self.done = true
        }
    }
}
