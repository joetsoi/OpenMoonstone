use ggez::Context;
use specs::{Read, ReadStorage, Resources, System, Write};
use warmy::{LogicalKey, Store, StoreOpt};

use crate::combat::components::draw::Draw;
use crate::combat::components::movement::Position;
use crate::objects::{Rect, TextureAtlas};

pub struct Renderer {
    store: Store<Context>,
}

impl<'a> System<'a> for Renderer {
    type SystemData = (
        ReadStorage<'a, Position>,
        ReadStorage<'a, Draw>,
    );

    fn run(&mut self, (position, draw): Self::SystemData) {
        use specs::Join;

        for (position, draw) in (&position, &draw).join() {
        }
    }
}
