use ggez_goodies::scene;

use crate::input;
use crate::game;

pub mod encounter;
pub mod menu;

pub use self::encounter::EncounterScene;
pub use self::menu::Menu;

pub type FSceneSwitch = scene::SceneSwitch<game::Game, input::InputEvent>;
pub type FSceneStack = scene::SceneStack<game::Game, input::InputEvent>;
