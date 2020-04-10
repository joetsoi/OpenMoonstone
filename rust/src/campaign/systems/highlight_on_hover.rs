// Highlights the active player on the map screen
use specs::{Join, ReadExpect, ReadStorage, System, WriteStorage};

use crate::campaign::components::{HitBox, OnHoverImage};
use crate::combat::components::{Controller, Draw, Position};
use crate::rect::Rect;

pub struct HighlightOnHover;

impl<'a> System<'a> for HighlightOnHover {
    type SystemData = (
        ReadStorage<'a, Position>,
        ReadStorage<'a, Controller>,
        ReadStorage<'a, HitBox>,
        ReadStorage<'a, OnHoverImage>,
        WriteStorage<'a, Draw>,
    );
    fn run(
        &mut self,
        (
            position_storage,
            controller_storage,
            hitbox_storage,
            on_hover_image_storage,
            mut draw_storage,
        ): Self::SystemData,
    ) {
        for (position, controller, hitbox) in
            (&position_storage, &controller_storage, &hitbox_storage).join()
        {
            for (loc_position, loc_onhoverimage, loc_hitbox, mut loc_draw) in (
                &position_storage,
                &on_hover_image_storage,
                &hitbox_storage,
                &mut draw_storage,
            )
                .join()
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
                loc_draw.frame.images.pop();
                if mover_rect.intersects(&loc_rect) {
                    if let Some(hover) = &loc_onhoverimage.hover {
                        loc_draw.frame.images.push(hover.clone());
                    }
                } else {
                    if let Some(image) = &loc_onhoverimage.image {
                        loc_draw.frame.images.push(image.clone());
                    }
                }
            }
        }
    }
}
