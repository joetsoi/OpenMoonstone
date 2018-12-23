use ggez_goodies::scene;

use crate::input;
use crate::game;

pub mod encounter;

pub type FSceneSwitch = scene::SceneSwitch<game::Game, input::InputEvent>;
pub type FSceneStack = scene::SceneStack<game::Game, input::InputEvent>;
