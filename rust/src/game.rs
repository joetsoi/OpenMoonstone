use crate::input;

pub struct Game {
    pub input: input::InputState,
}

impl Game {
    pub fn new() -> Game {
        Game {
            input: input::InputState::new(),
        }
    }
}
