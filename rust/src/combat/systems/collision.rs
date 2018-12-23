use std::collections::HashMap;

use lazy_static::lazy_static;
use maplit::hashmap;
use specs::{Entities, ReadExpect, ReadStorage, System, WriteStorage};

use crate::animation::ImageType;
use crate::combat::components::collision::{CollisionBox, Points};
use crate::combat::components::intent::{AttackType, DefendType};
use crate::combat::components::state::HitType;
use crate::combat::components::{
    Action, Body, Collided, Draw, Facing, Health, Position, State, Velocity, Weapon,
};
use crate::files::collide::CollisionBoxes;
use crate::scenes::encounter::EncounterTextures;
use crate::objects::TextureAtlas;
use crate::rect::{Interval, Point, Rect};

pub struct EntityEntityCollision;

impl<'a> System<'a> for EntityEntityCollision {
    type SystemData = (
        ReadStorage<'a, Body>,
        ReadStorage<'a, Position>,
        WriteStorage<'a, Velocity>,
        Entities<'a>,
    );

    fn run(
        &mut self,
        (body_storage, position_storage, mut velocity_storage, entities): Self::SystemData,
    ) {
        use specs::Join;
        for (body, position_1, velocity, entity_1) in (
            &body_storage,
            &position_storage,
            &mut velocity_storage,
            &*entities,
        )
            .join()
        {
            for (other, position_2, _entity_2) in (&body_storage, &position_storage, &*entities)
                .join()
                .filter(|(.., entity_2)| entity_2.id() != entity_1.id())
            {
                if let (Some(body_rect), Some(other_rect)) = (body.rect, other.rect) {
                    let y_delta: i32 = position_1.y as i32 - position_2.y as i32;
                    let new_rect = body_rect + (velocity.x, velocity.y);
                    if y_delta.abs() <= 20 {
                        if new_rect.intersects(&other_rect) {
                            let other_x = Interval {
                                a: other_rect.x,
                                b: other_rect.x + other_rect.w as i32,
                            };
                            if velocity.x < 0 && other_x.contains_point(new_rect.x) {
                                velocity.x = 0;
                            } else if velocity.x > 0
                                && other_x.contains_point(new_rect.x + new_rect.w as i32)
                            {
                                velocity.x = 0;
                            }

                            let other_y = Interval {
                                a: other_rect.y,
                                b: other_rect.y + new_rect.h as i32,
                            };
                            if velocity.y < 0 && other_y.contains_point(new_rect.y) {
                                velocity.y = 0;
                            } else if velocity.y > 0
                                && other_y.contains_point(new_rect.y + new_rect.h as i32)
                            {
                                velocity.y = 0;
                            }

                        }
                    }

                    // let y_delta: i32 = position_1.y as i32 - position_2.y as i32;
                    // if y_delta.abs() <= 10 && new_y.intersects(&other_y) {
                    //     println!("{:?}", new_y);
                    //     velocity.y = 0;
                    // }
                }
            }
        }
    }
}

pub struct UpdateBoundingBoxes;

impl<'a> System<'a> for UpdateBoundingBoxes {
    type SystemData = (
        ReadExpect<'a, CollisionBoxes>,
        ReadExpect<'a, EncounterTextures>,
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
                let mut contains_all: Option<Rect> = None;
                for body_box in &body_boxes {
                    match contains_all {
                        Some(ref mut rect) => {
                            if body_box.rect.w > rect.w {
                                rect.w = body_box.rect.w
                            }
                            if body_box.rect.h > rect.h {
                                rect.h = body_box.rect.h
                            }
                            if body_box.rect.x < rect.x {
                                rect.x = body_box.rect.x
                            }
                            if body_box.rect.y < rect.x {
                                rect.y = body_box.rect.y
                            }
                        }
                        None => contains_all = Some(body_box.rect.clone()),
                    }
                }
                body.collision_boxes = Some(body_boxes);
                body.rect = contains_all;
            }
        }
    }
}

pub struct CheckCollisions;

impl<'a> System<'a> for CheckCollisions {
    type SystemData = (
        ReadExpect<'a, EncounterTextures>,
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
        for (_state, att_pos, weapon, attacker) in (&state, &position, &weapons, &*entities)
            .join()
            .filter(|(state, ..)| state.action.is_attack())
        {
            for (defender, body, _defender_position) in (&*entities, &bodies, &position)
                .join()
                // ignore self for collision checking.
                .filter(|(defender, ..)| attacker.id() != defender.id())
                // ignore entities outside a 10 pixel y range.
                .filter(|(_, _, d_pos)| (att_pos.y as i32 - d_pos.y as i32).abs() < 10)
            {
                let hit = CheckCollisions::check_collision(&textures, weapon, body);
                if hit {
                    let _result = collided.insert(attacker, Collided { target: defender });
                }
            }
        }
    }
}

impl CheckCollisions {
    fn check_collision(
        textures: &HashMap<String, TextureAtlas>,
        weapon: &Weapon,
        body: &Body,
    ) -> bool {
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
}

lazy_static! {
    static ref blocks_attack: HashMap<Action, Action> = hashmap! {
        Action::Attack(AttackType::Swing) => Action::Defend(DefendType::Block),
        Action::Attack(AttackType::BackSwing) => Action::Defend(DefendType::Block),
        Action::Attack(AttackType::Thrust) => Action::Defend(DefendType::Dodge),
        Action::Attack(AttackType::Chop) => Action::Defend(DefendType::Dodge),
        Action::Attack(AttackType::UpThrust) => Action::Defend(DefendType::Dodge),
        Action::Attack(AttackType::ThrowDagger) => Action::Defend(DefendType::Dodge),
    };
}

pub struct ResolveCollisions;

impl<'a> System<'a> for ResolveCollisions {
    type SystemData = (
        WriteStorage<'a, Collided>,
        WriteStorage<'a, Health>,
        WriteStorage<'a, State>,
        Entities<'a>,
    );

    fn run(
        &mut self,
        (mut collided_storage, mut health_storage, mut state_storage, entities): Self::SystemData,
    ) {
        use specs::Join;
        for (collided, entity) in (collided_storage.drain(), &*entities).join() {
            let mut has_defended = false;
            let mut target_used_block = false;

            let target = &collided.target;
            {
                let state: Option<&State> = state_storage.get(entity);
                let target_state: Option<&State> = state_storage.get(*target);
                if let (Some(state), Some(target_state)) = (state, target_state) {
                    has_defended = blocks_attack
                        .get(&state.action)
                        .and_then(|a| Some(a == &target_state.action))
                        .expect(&format!(
                            "attack {:?} not in blocks_attack lookup",
                            &state.action
                        ));
                    target_used_block = target_state.action == Action::Defend(DefendType::Block);
                    if target_used_block && target_state.direction == state.direction {
                        has_defended = false;
                    }
                }
            }

            {
                if !has_defended {
                    // set defender animation
                    let target = &collided.target;
                    let target_health: Option<&mut Health> = health_storage.get_mut(*target);
                    let target_state: Option<&mut State> = state_storage.get_mut(*target);
                    if let (Some(target_health), Some(target_state)) = (target_health, target_state)
                    {
                        target_health.points -= 3; // TODO: change hard coded weapon damage
                        target_state.action = Action::Hit(HitType::Sliced);
                        target_state.ticks = 0;
                    }
                }
            }
            {
                // set attacker state
                let state: Option<&mut State> = state_storage.get_mut(entity);
                if let Some(state) = state {
                    if !has_defended || target_used_block {
                        match state.action {
                            Action::Attack(AttackType::UpThrust) => (),
                            _ => {
                                state.action = Action::AttackRecovery;
                                state.ticks = 0;
                            }
                        }
                    }
                }
            }
        }
    }
}
