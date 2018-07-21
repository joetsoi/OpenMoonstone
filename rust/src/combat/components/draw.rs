use specs::{Component, VecStorage};
//use specs_derive::*;
use crate::animation::Frame;

#[derive(Debug)]
pub struct Draw {
    pub frame: Frame,
}

impl Component for Draw {
    type Storage = VecStorage<Self>;
}
