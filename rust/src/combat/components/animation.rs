use specs::{Component, VecStorage};

#[derive(Debug, Default)]
pub struct AnimationState {
    pub frame_number: u32,
}

impl Component for AnimationState {
    type Storage = VecStorage<Self>;
}
