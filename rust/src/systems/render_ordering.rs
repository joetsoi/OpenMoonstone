use specs::{Join, ReadStorage, System, WriteStorage};

use crate::combat::components::Position;
use crate::components::RenderOrder;

pub struct SortRenderByYPosition;

impl<'a> System<'a> for SortRenderByYPosition {
    type SystemData = (ReadStorage<'a, Position>, WriteStorage<'a, RenderOrder>);
    fn run(&mut self, (position, mut render_order): Self::SystemData) {
        let mut storage = (&position, &mut render_order).join().collect::<Vec<_>>();
        storage.sort_by(|a, b| a.0.y.cmp(&b.0.y));

        let mut i = 0usize;
        for (_, render_order) in storage {
            render_order.depth = i;
            i += 1;
        }
    }
}
