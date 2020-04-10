use specs::{Component, VecStorage};
use specs_derive::*;

use crate::animation::Image;

#[derive(Component, Debug, Default)]
#[storage(VecStorage)]
pub struct OnHoverImage {
    pub image: Option<Image>,
    pub hover: Option<Image>,
}
