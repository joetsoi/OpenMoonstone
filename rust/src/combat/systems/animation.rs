use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{AnimationState, Command, Direction, Draw, Intent, WalkingState};

lazy_static! {
    static ref command_to_animation: HashMap<Command, String> = hashmap!{
        Command::Idle => "idle".to_string(),
        Command::Move(Direction::TryMoveUp) => "up".to_string(),
        Command::Move(Direction::TryMoveDown) => "down".to_string(),
        Command::Move(Direction::TryMoveLeft) => "walk".to_string(),
        Command::Move(Direction::TryMoveRight) => "walk".to_string(),
        Command::Move(Direction::TryMoveLeftUp) => "walk".to_string(),
        Command::Move(Direction::TryMoveRightUp) => "walk".to_string(),
        Command::Move(Direction::TryMoveLeftDown) => "walk".to_string(),
        Command::Move(Direction::TryMoveRightDown) => "walk".to_string(),
    };
}

pub struct Animation;

impl<'a> System<'a> for Animation {
    type SystemData = (
        ReadStorage<'a, Intent>,
        ReadStorage<'a, WalkingState>,
        WriteStorage<'a, AnimationState>,
        WriteStorage<'a, Draw>,
    );

    fn run(&mut self, (intent, walking_state, mut animation_state, mut draw): Self::SystemData) {
        use specs::Join;
        for (intent, walking_state, animation_state, draw) in
            (&intent, &walking_state, &mut animation_state, &mut draw).join()
        {
            draw.animation = command_to_animation[&intent.command].clone();
            match draw.animation.as_str() {
                "idle" => animation_state.frame_number = 0,
                _ => animation_state.frame_number = walking_state.step,
            }
        }
    }
}
