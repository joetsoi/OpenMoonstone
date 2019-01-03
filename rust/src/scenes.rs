use ggez_goodies::scene;

use crate::game;
use crate::input;

pub mod encounter;
pub mod main;
pub mod menu;
pub mod transition;

pub use self::encounter::EncounterScene;
pub use self::main::MainScene;
pub use self::menu::Menu;
pub use self::transition::Fade;

pub type FSceneSwitch = scene::SceneSwitch<game::Game, input::InputEvent>;
pub type FSceneStack = scene::SceneStack<game::Game, input::InputEvent>;
