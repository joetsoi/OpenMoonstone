// Checks
use specs::{Entities, Join, ReadExpect, ReadStorage, System, WriteStorage};

use crate::campaign::components::{Interactable, HitBox, OnHoverImage};
use crate::combat::components::{Controller, Draw, Position};
use crate::rect::Rect;

pub struct CheckMapCollision;

impl<'a> System<'a> for CheckMapCollision {
    type SystemData = (
        ReadStorage<'a, Position>,
        ReadStorage<'a, Controller>,
        ReadStorage<'a, HitBox>,
        WriteStorage<'a, Interactable>,
        Entities<'a>,
    );
    fn run(
        &mut self,
        (position_storage, controller_storage, hitbox_storage, mut interact_storage, entities): Self::SystemData,
    ) {
        for (position, _, hitbox, moving_entity) in (
            &position_storage,
            &controller_storage,
            &hitbox_storage,
            &*entities,
        )
            .join()
        {
            for (loc_position, loc_hitbox, location) in
                (&position_storage, &hitbox_storage, &*entities).join()
            {
                let mover_rect = Rect {
                    x: position.x,
                    y: position.y,
                    w: hitbox.w,
                    h: hitbox.h,
                };
                let loc_rect = Rect {
                    x: loc_position.x,
                    y: loc_position.y,
                    w: loc_hitbox.w,
                    h: loc_hitbox.h,
                };
                if mover_rect.intersects(&loc_rect) {
                    let result =
                        interact_storage.insert(location, Interactable { target:  moving_entity });
                } else {
                    interact_storage.remove(location);
                }
            }
        }
    }
}
