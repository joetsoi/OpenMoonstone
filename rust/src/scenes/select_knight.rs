use failure::Error;
use ggez::{graphics, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use warmy::{LogicalKey, Store};

use crate::game::{Game, SceneState};
use crate::input::{Axis, Button, InputEvent};
use crate::scenes::FSceneSwitch;

use super::menu::Menu;

pub struct SelectKnight {
    menu: Menu,
}

impl SelectKnight {
    pub fn new(ctx: &mut Context, store: &mut Store<Context>) -> Result<Self, Error> {
        let menu = Menu::new(ctx, store, "/select_knight.yaml")?;
        Ok(Self {
            menu,
        })
    }

}

impl Scene<Game, InputEvent> for SelectKnight {
    fn update(&mut self, _game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        SceneSwitch::None
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        graphics::set_background_color(ctx, graphics::Color::from((0, 0, 0, 255)));
        graphics::clear(ctx);
        self.menu.draw(game, ctx);
        Ok(())
    }

    fn name(&self) -> &str {
        "Select a Knight"
    }

    fn input(&mut self, gameworld: &mut Game, _event: InputEvent, started: bool) {}
}
