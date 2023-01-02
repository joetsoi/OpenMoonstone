// use ggez_goodies::scene;

use crate::game;
use crate::input;
use crate::scenestack;

pub mod encounter;
// pub mod main;
// pub mod main_menu;
// pub mod map;
// pub mod menu;
// pub mod next_day;
// pub mod select_knight;
// pub mod transition;
// pub mod world;

pub use self::encounter::{EncounterBuilder, EncounterScene};
// pub use self::main::MainScene;
// pub use self::main_menu::MainMenuScene;
// pub use self::map::MapScene;
// pub use self::next_day::NextDay;
// pub use self::select_knight::SelectKnight;
// pub use self::transition::Fade;

pub type FSceneSwitch = scenestack::SceneSwitch<game::Game, input::InputEvent>;
pub type FSceneStack = scenestack::SceneStack<game::Game, input::InputEvent>;
