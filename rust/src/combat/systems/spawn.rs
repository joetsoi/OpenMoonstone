use specs::{Entities, Join, LazyUpdate, Read, System, WriteStorage};

use crate::combat::components::SpawnPool;

pub struct SpawnControl;

impl<'a> System<'a> for SpawnControl {
    type SystemData = (
        WriteStorage<'a, SpawnPool>,
        Read<'a, LazyUpdate>,
        Entities<'a>,
    );
    fn run(&mut self, (mut spawn_pool, lazy, entities): Self::SystemData) {
        for spawn_pool in (&mut spawn_pool).join() {
            spawn_pool.spawn_lazy(&lazy, &entities);
        }
    }
}
