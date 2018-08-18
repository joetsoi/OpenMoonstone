use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::{AnimationState, Controller, Draw, WalkingState};

const IDLE: (i32, i32) = (0, 0);
const UP: (i32, i32) = (0, -1);
const DOWN: (i32, i32) = (0, 1);
const LEFT: (i32, i32) = (-1, 0);
const RIGHT: (i32, i32) = (1, 0);
const LEFT_UP: (i32, i32) = (-1, -1);
const RIGHT_UP: (i32, i32) = (1, -1);
const LEFT_DOWN: (i32, i32) = (-1, 1);
const RIGHT_DOWN: (i32, i32) = (1, 1);

lazy_static! {
    static ref controller_to_animation: HashMap<(i32, i32), String> = hashmap!{
        IDLE => "idle".to_string(),
        UP => "up".to_string(),
        DOWN => "down".to_string(),
        LEFT => "walk".to_string(),
        RIGHT => "walk".to_string(),
        LEFT_UP => "walk".to_string(),
        RIGHT_UP => "walk".to_string(),
        LEFT_DOWN => "walk".to_string(),
        RIGHT_DOWN => "walk".to_string(),
    };
}

pub struct Animation;

impl<'a> System<'a> for Animation {
    type SystemData = (
        ReadStorage<'a, Controller>,
        ReadStorage<'a, WalkingState>,
        WriteStorage<'a, AnimationState>,
        WriteStorage<'a, Draw>,
    );

    fn run(
        &mut self,
        (controller, walking_state, mut animation_state, mut draw): Self::SystemData,
    ) {
        use specs::Join;
        for (controller, walking_state, animation_state, draw) in
            (&controller, &walking_state, &mut animation_state, &mut draw).join()
        {
            draw.animation = controller_to_animation[&(controller.x, controller.y)].clone();
            match draw.animation.as_str() {
                "idle" => animation_state.frame_number = 0,
                _ => animation_state.frame_number = walking_state.step,
            }
        }
    }
}
