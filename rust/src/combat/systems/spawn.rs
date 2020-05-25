use specs::{Entities, Join, LazyUpdate, Read, ReadStorage, System, WriteStorage};

use crate::combat::components::{
    AnimationState,
    Body,
    DaggersInventory,
    Draw,
    Facing,
    Health,
    Intent,
    MustLive,
    Palette,
    Position,
    SpawnPool,
    State,
    UnitType,
    Velocity,
    WalkingState,
    Weapon,
};
use crate::components::RenderOrder;

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
