use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{AttackType, XAxis, YAxis};
use crate::combat::components::state::HitType;
use crate::combat::components::{
    Action, AnimationState, Draw, State, TouchingBoundary, WalkingState,
};

lazy_static! {
    static ref action_to_animation: HashMap<Action, String> = hashmap!{
        Action::Idle => "idle".to_string(),
        Action::Hit(HitType::Sliced) => "hit".to_string(),
        //Action::Move { x: XAxis::Centre, y: YAxis::Centre } => "idle".to_string(),
        Action::Move { x: XAxis::Centre, y: YAxis::Up } => "up".to_string(),
        Action::Move { x: XAxis::Centre, y: YAxis::Down } => "down".to_string(),
        Action::Move { x: XAxis::Left, y: YAxis::Centre } => "walk".to_string(),
        Action::Move { x: XAxis::Right, y: YAxis::Centre } => "walk".to_string(),
        Action::Move { x: XAxis::Left, y: YAxis::Up } => "walk".to_string(),
        Action::Move { x: XAxis::Right, y: YAxis::Up } => "walk".to_string(),
        Action::Move { x: XAxis::Left, y: YAxis::Down } => "walk".to_string(),
        Action::Move { x: XAxis::Right, y: YAxis::Down } => "walk".to_string(),
        Action::Attack(AttackType::BackSwing) => "back_swing".to_string(),
        Action::Attack(AttackType::Chop) => "chop".to_string(),
        Action::Attack(AttackType::Swing) => "swing".to_string(),
        Action::Attack(AttackType::ThrowDagger) => "throw_dagger".to_string(),
        Action::Attack(AttackType::Thrust) => "thrust".to_string(),
        Action::Attack(AttackType::UpThrust) => "up_thrust".to_string(),
        Action::AttackRecovery => "recovery".to_string(),
    };
}

pub struct Animation;

impl<'a> System<'a> for Animation {
    type SystemData = (
        //ReadStorage<'a, Intent>,
        ReadStorage<'a, WalkingState>,
        ReadStorage<'a, TouchingBoundary>,
        WriteStorage<'a, AnimationState>,
        WriteStorage<'a, Draw>,
        ReadStorage<'a, State>,
    );

    fn run(
        &mut self,
        (walking_state, touching_boundary, mut animation_state, mut draw, state): Self::SystemData,
    ) {
        use specs::Join;
        for (walking_state, touching_boundary, animation_state, draw, state) in (
            //&intent,
            &walking_state,
            &touching_boundary,
            &mut animation_state,
            &mut draw,
            &state,
        )
            .join()
        {
            match state.action {
                Action::Idle => {
                    animation_state.frame_number = 0;
                }
                Action::Attack(..) | Action::Hit(..) | Action::AttackRecovery => {
                    animation_state.frame_number = state.ticks;
                }
                _ => animation_state.frame_number = walking_state.step,
            }
            draw.animation = action_to_animation[&state.action].clone();
        }
    }
}
