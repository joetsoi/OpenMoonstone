use std::collections::HashMap;

use specs::{Entities, Read, ReadStorage, System, WriteStorage};

use crate::animation::ImageType;
use crate::combat::components::collision::{CollisionBox, Points};
use crate::combat::components::{
    Action, Body, Collided, Draw, Facing, Health, Position, State, Weapon,
};
use crate::files::collide::CollisionBoxes;
use crate::game::EncounterTextures;
use crate::objects::TextureAtlas;
use crate::rect::{Point, Rect};

pub struct UpdateBoundingBoxes;

impl<'a> System<'a> for UpdateBoundingBoxes {
    type SystemData = (
        Read<'a, CollisionBoxes>,
        Read<'a, EncounterTextures>,
        ReadStorage<'a, Draw>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, State>,
        WriteStorage<'a, Body>,
        WriteStorage<'a, Weapon>,
    );

    fn run(
        &mut self,
        (
            collision_boxes,
            encounter_textures,
            draw,
            position,
            state,
            mut body,
            mut weapon,
        ): Self::SystemData,
    ) {
        use specs::Join;
        let collision_data = &collision_boxes.data;
        let textures = &encounter_textures.data;
        for (draw, position, state, body, weapon) in
            (&draw, &position, &state, &mut body, &mut weapon).join()
        {
            let mut weapon_boxes: Vec<Points> = vec![];
            let mut body_boxes: Vec<CollisionBox> = vec![];
            for image in draw.frame.images.iter() {
                match image.image_type {
                    ImageType::Collider => {
                        if let Some(Some(points)) = &collision_data
                            .get(&image.sheet)
                            .and_then(|v| v.points.get(image.image))
                        {
                            let direction = state.direction as i32;
                            let image_global_x: i32 = position.x as i32 + image.x * direction;
                            let image_global_y: i32 = position.y as i32 + image.y;
                            let rect_x = match state.direction {
                                Facing::Left => image_global_x - points.max_x as i32,
                                Facing::Right => image_global_x,
                            };
                            weapon_boxes.push(Points {
                                bounding: Rect {
                                    x: rect_x,
                                    y: image_global_y,
                                    w: points.max_x,
                                    h: points.max_y,
                                },
                                points: points
                                    .data
                                    .iter()
                                    .map(|p| Point {
                                        x: image_global_x + p.x * direction,
                                        y: image_global_y + p.y,
                                    })
                                    .collect(),
                            })
                        }
                    }
                    ImageType::Collidee => {
                        if let Some(texture) = textures.get(&image.sheet) {
                            let rect = &texture.rects[image.image];
                            let mut image_global_x: i32 =
                                position.x as i32 + image.x * state.direction as i32;
                            image_global_x = match state.direction {
                                Facing::Left => image_global_x - rect.w as i32,
                                Facing::Right => image_global_x,
                            };
                            body_boxes.push(CollisionBox {
                                rect: Rect {
                                    x: image_global_x,
                                    y: position.y as i32 + image.y,
                                    w: rect.w,
                                    h: rect.h,
                                },
                                sheet: image.sheet.clone(),
                                image_num: image.image as u32,
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

pub struct CheckCollisions;

impl<'a> System<'a> for CheckCollisions {
    type SystemData = (
        Read<'a, EncounterTextures>,
        ReadStorage<'a, State>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, Body>,
        ReadStorage<'a, Weapon>,
        WriteStorage<'a, Collided>,
        Entities<'a>,
    );

    fn run(
        &mut self,
        (encounter_textures, state, position, bodies, weapons, mut collided, entities): Self::SystemData,
    ) {
        use specs::Join;
        let textures = &encounter_textures.data;
        for (state, att_pos, weapon, attacker) in (&state, &position, &weapons, &*entities)
            .join()
            .filter(|(s, ..)| s.action.is_attack())
        {
            for (defender, body, defender_position) in (&*entities, &bodies, &position)
                .join()
                // ignore self for collision checking.
                .filter(|(defender, ..)| attacker.id() != defender.id())
                // ignore entities outside a 10 pixel y range.
                .filter(|(_, _, d_pos)| (att_pos.y as i32 - d_pos.y as i32).abs() < 10)
            {
                let hit = check_collision(&textures, weapon, body);
                if hit {
                    let result = collided.insert(attacker, Collided { target: defender });
                }
            }
        }
    }
}

fn check_collision(textures: &HashMap<String, TextureAtlas>, weapon: &Weapon, body: &Body) -> bool {
    for weapon_part in weapon.collision_points.iter().flat_map(|v| v) {
        // each attacking image in the attacker
        for body_part in body
            .collision_boxes
            .iter() // Option.iter()
            .flat_map(|v| v)
            .filter(|b| weapon_part.bounding.intersects(&b.rect))
        {
            // check that against each defending image in the defender
            for point in weapon_part
                .points
                .iter()
                .filter(|p| body_part.rect.contains_point(p))
            {
                // check the points collide and the pixel in the image is a part of the target
                let hit_x = point.x - body_part.rect.x;
                let hit_y = point.y - body_part.rect.y;
                let texture = textures
                    .get(&body_part.sheet)
                    .expect("Encounter hasn't loaded correct textures to as world resource");
                let collision_lookup = hit_x as usize * texture.image.width + hit_y as usize;
                let pixel = texture.image.pixels[collision_lookup];
                if pixel > 0 {
                    return true;
                }
            }
        }
    }
    false
}

pub struct ResolveCollisions;

impl<'a> System<'a> for ResolveCollisions {
    type SystemData = (
        WriteStorage<'a, Collided>,
        WriteStorage<'a, Health>,
        Entities<'a>,
    );

    fn run(&mut self, (mut collided_storage, mut health_storage, entities): Self::SystemData) {
        use specs::Join;
        for (collided, entity) in (collided_storage.drain(), &*entities).join() {
            let health: Option<&mut Health> = health_storage.get_mut(entity);
            if let Some(health) = health {
                health.points -= 3; // TODO: change hard coded weapon damage
                println!("collided {:?}", health);
            }
        }
    }
}
