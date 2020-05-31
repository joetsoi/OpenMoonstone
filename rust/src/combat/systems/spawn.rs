use specs::{world::Index, Entities, Join, LazyUpdate, Read, ReadStorage, System, WriteStorage};

use crate::combat::components::{Health, SpawnPool};

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

pub struct DestroySpawnPool;

impl<'a> System<'a> for DestroySpawnPool {
    type SystemData = (
        WriteStorage<'a, SpawnPool>,
        ReadStorage<'a, Health>,
        Entities<'a>,
    );
    fn run(&mut self, (mut spawn_pool, health, entities): Self::SystemData) {
        for (spawn_pool, spawn_entity) in (&mut spawn_pool, &*entities).join() {
            let dead: Vec<Index> = spawn_pool
                .active
                .iter()
                .filter(|&id| health.get(entities.entity(*id)).is_none())
                .cloned()
                .collect();

            for combatant_id in dead {
                spawn_pool.active.remove(&combatant_id);
            }
            if spawn_pool.is_empty() {
                entities
                    .delete(spawn_entity)
                    .expect("failed to delete spawn pool");
            }
        }
    }
}
