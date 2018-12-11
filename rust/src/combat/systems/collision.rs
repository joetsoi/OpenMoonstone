use specs::{Entities, Read, ReadStorage, System, WriteStorage};

use crate::animation::ImageType;
use crate::combat::components::collision::Points;
use crate::combat::components::{Action, Body, Draw, Position, State, Weapon};
use crate::files::collide::CollisionBoxes;
use crate::game::EncounterTextures;
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
            let mut body_boxes: Vec<Rect> = vec![];
            for image in draw.frame.images.iter() {
                match image.image_type {
                    ImageType::Collider => {
                        if let Some(collision_points) = collision_data.get(&image.sheet) {
                            if let Some(points) = &collision_points.points[image.image] {
                                let image_global_x: i32 =
                                    position.x as i32 + image.x * state.direction as i32;
                                let image_global_y: i32 = position.y as i32 + image.y;
                                weapon_boxes.push(Points {
                                    bounding: Rect {
                                        // x: image.x * state.direction as i32,
                                        // y: image.y,
                                        x: image_global_x,
                                        y: image_global_y,
                                        w: points.max_x as i32 * state.direction as i32,
                                        h: points.max_y as i32,
                                    },
                                    points: points
                                        .data
                                        .iter()
                                        .map(|p| Point {
                                            x: image_global_x + p.x * state.direction as i32,
                                            y: image_global_y + p.y,
                                            // x: p.x * state.direction as i32,
                                            // y: p.y,
                                        })
                                        .collect(),
                                })
                            }
                        }
                    }
                    ImageType::Collidee => {
                        if let Some(texture) = textures.get(&image.sheet) {
                            let rect = &texture.rects[image.image];
                            body_boxes.push(Rect {
                                x: position.x as i32 + image.x * state.direction as i32,
                                y: position.y as i32 + image.y,
                                w: rect.w * state.direction as i32,
                                h: rect.h,
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
        Entities<'a>,
    );

    fn run(
        &mut self,
        (encounter_textures, state, position, bodies, weapons, entities): Self::SystemData,
    ) {
        use specs::Join;
        let textures = &encounter_textures.data;
        for (state, attacker_position, weapon, attacker) in
            (&state, &position, &weapons, &*entities)
                .join()
                .filter(|(s, ..)| s.action.is_attack())
        {
            for (defender, body, defender_position) in (&*entities, &bodies, &position)
                .join()
                .filter(|(defender, ..)| attacker.id() != defender.id())
            {
                for weapon_part in weapon.collision_points.iter().flat_map(|v| v) {
                    for body_part in body
                        .collision_boxes
                        .iter() // Option.iter()
                        .flat_map(|v| v)
                        .filter(|b| weapon_part.bounding.intersects(b))
                        //.filter(|b| weapon_part.points.iter().any(|p| b.contains_point(p)))
                    {

                        println!("hit");
                        // for point in weapon_part.points.iter() {
                        //     println!("{:?} {:?}", point, body_part);
                        // }
                    }
                }
            }
        }
    }
}
