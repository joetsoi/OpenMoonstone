use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{XAxis, YAxis};
use crate::combat::components::{
    AnimationState, Command, Draw, Intent, TouchingBoundary, WalkingState,
};

lazy_static! {
    static ref command_to_animation: HashMap<Command, String> = hashmap!{
        Command::Idle => "idle".to_string(),
        Command::Move { x: XAxis::Centre, y: YAxis::Centre } => "idle".to_string(),
        Command::Move { x: XAxis::Centre, y: YAxis::Up } => "up".to_string(),
        Command::Move { x: XAxis::Centre, y: YAxis::Down } => "down".to_string(),
        Command::Move { x: XAxis::Left, y: YAxis::Centre } => "walk".to_string(),
        Command::Move { x: XAxis::Right, y: YAxis::Centre } => "walk".to_string(),
        Command::Move { x: XAxis::Left, y: YAxis::Up } => "walk".to_string(),
        Command::Move { x: XAxis::Right, y: YAxis::Up } => "walk".to_string(),
        Command::Move { x: XAxis::Left, y: YAxis::Down } => "walk".to_string(),
        Command::Move { x: XAxis::Right, y: YAxis::Down } => "walk".to_string(),
    };
}

pub struct Animation;

impl<'a> System<'a> for Animation {
    type SystemData = (
        ReadStorage<'a, Intent>,
        ReadStorage<'a, WalkingState>,
        ReadStorage<'a, TouchingBoundary>,
        WriteStorage<'a, AnimationState>,
        WriteStorage<'a, Draw>,
    );

    fn run(
        &mut self,
        (intent, walking_state, touching_boundary, mut animation_state, mut draw): Self::SystemData,
    ) {
        use specs::Join;
        for (intent, walking_state, touching_boundary, animation_state, draw) in (
            &intent,
            &walking_state,
            &touching_boundary,
            &mut animation_state,
            &mut draw,
        )
            .join()
        {
            let command = match intent.command {
                Command::Move { x, y } => {
                    let mut actual_x = x;
                    let mut actual_y = y;
                    if touching_boundary.left || touching_boundary.right {
                        actual_x = XAxis::Centre;
                    }
                    if touching_boundary.top || touching_boundary.bottom {
                        actual_y = YAxis::Centre;
                    }
                    Command::Move {
                        x: actual_x,
                        y: actual_y,
                    }
                }
                _ => intent.command.clone(),
            };
            draw.animation = command_to_animation[&command].clone();
            match draw.animation.as_str() {
                "idle" => animation_state.frame_number = 0,
                _ => animation_state.frame_number = walking_state.step,
            }
        }
    }
}
