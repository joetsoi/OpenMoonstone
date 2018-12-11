use specs::{Read, ReadStorage, System, WriteStorage};

use crate::animation::{ImageType, SpriteData};
use crate::combat::components::collision::Points;
use crate::combat::components::{Body, Draw, Position, State, Weapon};
use crate::files::collide::CollisionBoxes;
use crate::game::ImageMetadata;
use crate::rect::Rect;

pub struct UpdateBoundingBoxes;

impl<'a> System<'a> for UpdateBoundingBoxes {
    type SystemData = (
        Read<'a, CollisionBoxes>,
        Read<'a, SpriteData>,
        Read<'a, ImageMetadata>,
        ReadStorage<'a, Draw>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, State>,
        WriteStorage<'a, Body>,
        WriteStorage<'a, Weapon>,
    );

    fn run(
        &mut self,
        (collision_boxes, sprite_data, image_metadata, draw, position, state, mut body, mut weapon): Self::SystemData,
    ) {
        use specs::Join;
        let collision_data = &collision_boxes.data;
        let sprites = &sprite_data.sprites;
        let image_sizes = &image_metadata.data;
        for (draw, position, state, body, weapon) in
            (&draw, &position, &state, &mut body, &mut weapon).join()
        {
            let mut weapon_boxes: Vec<Points> = vec![];
            let mut body_boxes: Vec<Rect> = vec![];
            for image in draw.frame.images.iter() {
                // TODO: facing
                match image.image_type {
                    ImageType::Collider => {
                        if let Some(collision_points) = collision_data.get(&image.sheet) {
                            if let Some(points) = &collision_points.points[image.image] {
                                weapon_boxes.push(Points {
                                    bounding: Rect {
                                        x: image.x * state.direction as i32,
                                        y: image.y,
                                        w: points.max_x as i32 * state.direction as i32,
                                        h: points.max_y as i32,
                                    },
                                    points: points.data.clone(),
                                })
                            }
                        }
                    }
                    ImageType::Collidee => {
                        if let Some(images_meta) = image_sizes.get(&image.sheet) {
                            let image_meta = &images_meta[image.image];
                            body_boxes.push(Rect {
                                x: image.x * state.direction as i32,
                                y: image.y,
                                w: image_meta.w * state.direction as i32,
                                h: image_meta.h,
                            })
                        }
                    }
                    _ => (),
                }
            }

            if weapon_boxes.is_empty() {
                weapon.collision_points = None;
            } else {
                weapon.collision_points = Some(weapon_boxes);
            }

            if body_boxes.is_empty() {
                body.collision_boxes = None;
            } else {
                body.collision_boxes = Some(body_boxes);
            }
        }
    }
}
