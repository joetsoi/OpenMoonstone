use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use failure::Error;
use ggez::conf::NumSamples;
use ggez::graphics;
use ggez::timer;
use ggez::{Context, GameResult};
use ggez_goodies::scene;
use specs::world::{Builder, Index};
use specs::{Dispatcher, DispatcherBuilder, Entity, Join, World};
use warmy::{LogicalKey, Store};

use super::transition::FadeStyle;
use super::Fade;
use crate::animation::{Image, ImageType, Sprite, SpriteData};
use crate::combat::components::{
    AnimationState, Body, Collided, Controller, DaggersInventory, Draw, Facing, Health, Intent,
    MustLive, Palette, Position, State, UnitType, Velocity, WalkingState, Weapon,
};
use crate::combat::damage::DamageTables;
use crate::combat::systems::boundary::TopBoundary;
use crate::combat::systems::health::CombatDone;
use crate::combat::systems::{
    ActionSystem, Animation, CheckCollisions, CheckEndOfCombat, Commander, ConfirmVelocity,
    EntityDeath, EntityEntityCollision, Movement, OutOfBounds, ResolveCollisions,
    RestrictMovementToBoundary, StateUpdater, UpdateBoundingBoxes, UpdateImage, VelocitySystem,
};
use crate::files::collide::CollisionBoxes;
use crate::files::terrain::scenery_rects;
use crate::files::TerrainFile;
use crate::game::{Game, SceneState};
use crate::input;
use crate::manager::GameYaml;
use crate::objects::TextureAtlas;
use crate::palette::PaletteSwaps;
use crate::piv::{palette_swap, Colour, PivImage};
use crate::rect::Rect;
use crate::scenes::FSceneSwitch;

#[derive(Debug, Default, Clone)]
pub struct EncounterTextures {
    pub data: HashMap<String, TextureAtlas>,
}

const TICKS_TO_WAIT: u32 = 35;

pub struct EncounterScene<'a> {
    pub specs_world: World,
    pub dispatcher: Dispatcher<'a, 'a>,
    pub background: graphics::Canvas,
    pub palette: Vec<Colour>,

    knight_id: Index,
    player_2: Index,

    // the number of ticks since the encounter is done
    ticks_after: u32,
    // we do the fade out first, pop back to this scene then pop the encounter.
    fade_out_done: bool,
}

impl<'a> EncounterScene<'a> {
    fn build_world() -> World {
        let mut world = World::new();
        world.register::<AnimationState>();
        world.register::<Body>();
        world.register::<Collided>();
        world.register::<Controller>();
        world.register::<DaggersInventory>();
        world.register::<Draw>();
        world.register::<Health>();
        world.register::<Intent>();
        world.register::<MustLive>();
        world.register::<Palette>();
        world.register::<Position>();
        world.register::<State>();
        world.register::<UnitType>();
        world.register::<Velocity>();
        world.register::<WalkingState>();
        world.register::<Weapon>();
        world
    }

    fn build_dispatcher() -> Dispatcher<'a, 'a> {
        DispatcherBuilder::new()
            .with(Commander, "commander", &[])
            .with(ActionSystem, "action", &["commander"])
            .with(EntityDeath, "entity_death", &["action"])
            .with(CheckEndOfCombat, "check_end_of_combat", &["entity_death"])
            .with(VelocitySystem, "velocity", &["commander"])
            .with(EntityEntityCollision, "entity_collision", &["velocity"])
            .with(
                RestrictMovementToBoundary,
                "restrict_movement_to_boundary",
                &["velocity"],
            )
            .with(
                ConfirmVelocity,
                "confirm_velocity",
                &["restrict_movement_to_boundary", "entity_collision"],
            )
            .with(Movement, "movement", &["confirm_velocity"])
            .with(Animation, "animation", &["movement"])
            //.with(StateUpdater, "state_updater", &["animation"])
            .with(UpdateImage, "update_image", &["animation"])
            .with(
                UpdateBoundingBoxes,
                "update_bounding_boxes",
                &["update_image"],
            )
            .with(
                CheckCollisions,
                "check_collisions",
                &["update_bounding_boxes"],
            )
            .with(
                ResolveCollisions,
                "resolve_collisions",
                &["check_collisions"],
            )
            .with(StateUpdater, "state_updater", &["resolve_collisions"])
            .with(OutOfBounds, "out_of_bounds", &[])
            // .with_thread_local(Renderer {
            //     store: Store::new(StoreOpt::default()).expect("store creation"),
            // })
            .build()
    }

    fn load_resources(
        ctx: &mut Context,
        store: &mut Store<Context>,
        world: &mut World,
    ) -> Result<(), Error> {
        let damage_tables = store
            .get::<_, DamageTables>(&LogicalKey::new("/damage.yaml"), ctx)
            .expect("error loading damage.yaml");
        world.add_resource(damage_tables.borrow().clone());
        world.add_resource(CombatDone(false));
        Ok(())
    }

    fn load_sprite_data(
        ctx: &mut Context,
        store: &mut Store<Context>,
        world: &mut World,
        entity_names: &[&str],
    ) -> Result<(), Error> {
        let entities_yaml =
            store.get::<_, GameYaml>(&warmy::LogicalKey::new("/entities.yaml"), ctx)?;

        let mut sprites: HashMap<String, Sprite> = HashMap::new();
        let mut atlas_names: HashSet<String> = HashSet::new();
        for name in entity_names {
            let yaml_borrow = &entities_yaml.borrow();
            let yaml_file = yaml_borrow.yaml[name].as_str().unwrap();
            let entity_yaml = store.get::<_, Sprite>(&warmy::LogicalKey::new(yaml_file), ctx)?;
            sprites.insert(name.to_string(), (*entity_yaml.borrow()).clone());

            for i in entity_yaml
                .borrow()
                .animations
                .values()
                .map(|a| &a.frames)
                .flatten()
                .map(|f| &f.images)
                .flatten()
                .map(|i| &i.sheet)
            {
                atlas_names.insert(i.clone());
            }
        }
        world.add_resource(SpriteData { sprites });
        let mut image_sizes: HashMap<String, Vec<Rect>> = HashMap::new();
        let mut texture_atlases: HashMap<String, TextureAtlas> = HashMap::new();
        for atlas_name in atlas_names {
            let atlas = store
                .get::<_, TextureAtlas>(&LogicalKey::new(atlas_name.clone()), ctx)
                .unwrap();
            image_sizes.insert(atlas_name.clone(), atlas.borrow().rects.clone());
            texture_atlases.insert(atlas_name.clone(), atlas.borrow().clone());
        }
        world.add_resource(EncounterTextures {
            data: texture_atlases,
        });
        Ok(())
    }

    fn create_entity(
        ctx: &mut Context,
        store: &mut Store<Context>,
        world: &mut World,
        resource: &str,
        raw_palette: &Vec<u16>,
        palette_name: &str,
        x: i32,
        y: i32,
        direction: Facing,
    ) -> Entity {
        let sprite_res = store
            .get::<_, Sprite>(&LogicalKey::new(format!("/{}.yaml", resource)), ctx)
            .unwrap();
        let sprite = sprite_res.borrow();

        let swaps_res = store
            .get::<_, PaletteSwaps>(&LogicalKey::new("/palettes.yaml"), ctx)
            .expect("error loading palette.yaml");
        let swaps = swaps_res.borrow();
        world
            .create_entity()
            .with(UnitType {
                name: resource.to_string(),
            })
            .with(Palette {
                name: palette_name.to_string(),
                palette: palette_swap(
                    &raw_palette,
                    &swaps.0.get(&palette_name.to_string()).expect("no palette"),
                ),
            })
            .with(MustLive {})
            .with(Controller {
                x: 0,
                y: 0,
                fire: false,
            })
            .with(Position { x: x, y: y })
            .with(Health {
                ..Default::default()
            })
            .with(Draw {
                frame: sprite.animations["entrance"].frames[0].clone(),
                animation: "entrance".to_string(),
                resource_name: resource.to_string(),
                direction: direction,
            })
            .with(Intent {
                ..Default::default()
            })
            .with(WalkingState {
                ..Default::default()
            })
            .with(Velocity {
                ..Default::default()
            })
            .with(AnimationState {
                ..Default::default()
            })
            .with(State {
                direction: direction,
                ..Default::default()
            })
            .with(Body {
                ..Default::default()
            })
            .with(Weapon {
                ..Default::default()
            })
            .with(DaggersInventory {
                ..Default::default()
            })
            .build()
    }

    pub fn new(
        ctx: &mut Context,
        game: &mut Game,
        entity_names: &[&str],
        background_name: &str,
        terrain_name: &str,
    ) -> Result<Self, Error> {
        let mut world = EncounterScene::build_world();
        EncounterScene::load_sprite_data(ctx, &mut game.store, &mut world, entity_names)?;
        EncounterScene::load_resources(ctx, &mut game.store, &mut world)?;

        let piv = game
            .store
            .get::<_, PivImage>(&LogicalKey::new(background_name), ctx)
            .unwrap();
        let background_image =
            graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8()).unwrap();
        let background = graphics::Canvas::new(ctx, 320, 200, NumSamples::One)?;
        graphics::set_canvas(ctx, Some(&background));
        let screen_origin = graphics::Point2::new(0.0, 0.0);
        graphics::draw_ex(
            ctx,
            &background_image,
            graphics::DrawParam {
                dest: screen_origin,
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;

        EncounterScene::draw_terrain(ctx, game, &mut world, terrain_name, &background);
        let collide_hit = game
            .store
            .get::<_, CollisionBoxes>(&LogicalKey::new("collide"), ctx)
            .unwrap();
        world.add_resource(collide_hit.borrow().clone());

        let knight = EncounterScene::create_entity(
            ctx,
            &mut game.store,
            &mut world,
            "knight",
            &piv.borrow().raw_palette,
            "green_knight",
            30,
            100,
            Facing::default(),
        );

        let player_2 = EncounterScene::create_entity(
            ctx,
            &mut game.store,
            &mut world,
            "knight",
            &piv.borrow().raw_palette,
            "blue_knight",
            250,
            100,
            Facing::Left,
        );
        let palette: Vec<Colour> = piv.borrow().palette.to_vec();
        Ok(Self {
            palette,
            specs_world: world,
            dispatcher: EncounterScene::build_dispatcher(),
            background,
            knight_id: knight.id(),
            player_2: player_2.id(),
            ticks_after: 0,
            fade_out_done: false,
        })
    }

    fn draw_terrain(
        ctx: &mut Context,
        game: &mut Game,
        world: &mut World,
        terrain_name: &str,
        background_image: &graphics::Canvas,
    ) -> Result<(), Error> {
        let terrain = game
            .store
            .get::<_, TerrainFile>(&LogicalKey::new(terrain_name.to_string()), ctx)
            .unwrap();
        for p in &terrain.borrow().positions {
            let cmp = game
                .store
                .get::<_, PivImage>(&LogicalKey::new(&p.atlas), ctx)?;
            let ggez_image = match game.images.entry(p.atlas.clone()) {
                Occupied(i) => i.into_mut(),
                Vacant(i) => i.insert(graphics::Image::from_rgba8(
                    ctx,
                    512u16,
                    512u16,
                    &cmp.borrow().to_rgba8_512(),
                )?),
            };

            let rect = scenery_rects[p.image_number];
            // println!("{:#?}",rect);

            let draw_params = graphics::DrawParam {
                src: graphics::Rect {
                    x: rect.x as f32 / 512.0,
                    y: rect.y as f32 / 512.0,
                    w: rect.w as f32 / 512.0,
                    h: rect.h as f32 / 512.0,
                },
                dest: graphics::Point2::new(p.x as f32 * 3.0, p.y as f32 * 3.0),
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            };
            graphics::draw_ex(ctx, ggez_image, draw_params)?;
        }
        graphics::set_canvas(ctx, None);
        world.add_resource(TopBoundary {
            y: terrain.borrow().boundary.h as i32,
        });
        Ok(())
    }

    fn update_controllers(&mut self, input: &input::InputState) {
        let entities = self.specs_world.entities();
        let mut controllers = self.specs_world.write_storage::<Controller>();
        for (e, controller) in (&*entities, &mut controllers).join() {
            if e.id() == self.knight_id {
                controller.x = input.get_axis_raw(input::Axis::Horz1) as i32;
                controller.y = input.get_axis_raw(input::Axis::Vert1) as i32;
                controller.fire = input.get_button_down(input::Button::Fire1);
            } else if e.id() == self.player_2 {
                controller.x = input.get_axis_raw(input::Axis::Horz2) as i32;
                controller.y = input.get_axis_raw(input::Axis::Vert2) as i32;
                controller.fire = input.get_button_down(input::Button::Fire2);
            }
        }
    }
}

impl<'a> scene::Scene<Game, input::InputEvent> for EncounterScene<'a> {
    fn update(&mut self, game: &mut Game, ctx: &mut Context) -> FSceneSwitch {
        self.specs_world.maintain();
        self.update_controllers(&game.input);
        self.dispatcher.dispatch_par(&self.specs_world.res);
        if self.specs_world.read_resource::<CombatDone>().0 {
            self.ticks_after += 1;
            if self.ticks_after > TICKS_TO_WAIT {
                match self.fade_out_done {
                    false => {
                        game.next_scene = SceneState::Menu;
                        return scene::SceneSwitch::push(Fade::new(274, 1, FadeStyle::Out));
                    }
                    true => return scene::SceneSwitch::Pop, //shouldn't happen
                }
            }
        }
        scene::SceneSwitch::None
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        //fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        //self.dispatcher.dispatch_thread_local(&self.game.world.res);
        // graphics::set_background_color(ctx, graphics::Color::from((0, 0, 0, 255)));
        // graphics::clear(ctx);

        let screen_origin = graphics::Point2::new(0.0, 0.0);
        // draw background
        let lair = &self.background;
        graphics::draw_ex(
            ctx,
            lair,
            graphics::DrawParam {
                dest: screen_origin,
                // TODO: this shouldn't be need investigate why it is.
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;
        let position_storage = self.specs_world.read_storage::<Position>();
        let draw_storage = self.specs_world.read_storage::<Draw>();
        let entities = self.specs_world.entities();

        let palette_storage = self.specs_world.read_storage::<Palette>();

        let mut storage = (&position_storage, &draw_storage, &entities)
            .join()
            .collect::<Vec<_>>();
        storage.sort_by(|&a, &b| a.0.y.cmp(&b.0.y));

        for (position, draw, entity) in storage {
            let images: Vec<&Image> = match game.gore_on {
                true => draw.frame.images.iter().collect(),
                false => draw.frame.images.iter().filter(|i| !i.is_blood()).collect(),
            };
            for image in images {
                let atlas = game
                    .store
                    .get::<_, TextureAtlas>(&LogicalKey::new(image.sheet.as_str()), ctx)
                    .unwrap();

                let atlas_dimension = atlas.borrow().image.width as u32;
                // TODO: change with palettes
                let palette: Option<&Palette> = palette_storage.get(entity);
                let ggez_image = match palette {
                    None => {
                        let ggez_image = match game.images.entry(image.sheet.clone()) {
                            Occupied(i) => i.into_mut(),
                            Vacant(i) => i.insert(
                                graphics::Image::from_rgba8(
                                    ctx,
                                    atlas_dimension as u16,
                                    atlas_dimension as u16,
                                    &atlas.borrow().image.to_rgba8(&self.palette),
                                )
                                .unwrap(),
                            ),
                        };
                        ggez_image
                    }
                    Some(palette) => {
                        let image_name = [image.sheet.clone(), palette.name.clone()].join("-");
                        let ggez_image = match game.images.entry(image_name) {
                            Occupied(i) => i.into_mut(),
                            Vacant(i) => i.insert(
                                graphics::Image::from_rgba8(
                                    ctx,
                                    atlas_dimension as u16,
                                    atlas_dimension as u16,
                                    &atlas.borrow().image.to_rgba8(&palette.palette),
                                )
                                .unwrap(),
                            ),
                        };
                        ggez_image
                    }
                };

                // Debug collision rects
                let rect = atlas.borrow().rects[image.image];
                let texture_size = atlas.borrow().image.width as f32;
                let draw_params = graphics::DrawParam {
                    src: graphics::Rect {
                        x: rect.x as f32 / texture_size,
                        y: rect.y as f32 / texture_size,
                        w: rect.w as f32 / texture_size,
                        h: rect.h as f32 / texture_size,
                    },
                    dest: graphics::Point2::new(
                        (position.x as i32 + (draw.direction as i32 * image.x)) as f32 * 3.0,
                        (position.y as i32 + image.y) as f32 * 3.0,
                    ),
                    scale: graphics::Point2::new((draw.direction as i32 * 3) as f32, 3.0),
                    ..Default::default()
                };

                graphics::draw_ex(ctx, ggez_image, draw_params)?;
                match image.image_type {
                    ImageType::BloodStain => {
                        graphics::set_canvas(ctx, Some(&self.background));
                        graphics::draw_ex(ctx, ggez_image, draw_params)?;
                        graphics::set_canvas(ctx, None);
                    }
                    _ => (),
                }
            }
        }

        let body_storage = self.specs_world.read_storage::<Body>();

        graphics::set_color(ctx, graphics::Color::new(0.4, 1.0, 0.0, 1.0))?;
        for body in (&body_storage).join() {
            if let Some(boxes) = &body.collision_boxes {
                for collision_box in boxes {
                    graphics::rectangle(
                        ctx,
                        graphics::DrawMode::Line(1.0),
                        graphics::Rect {
                            x: (collision_box.rect.x) as f32 * 3.0,
                            y: (collision_box.rect.y) as f32 * 3.0,
                            w: collision_box.rect.w as f32 * 3.0,
                            h: collision_box.rect.h as f32 * 3.0,
                        },
                    )?;
                }
            }
        }

        let weapon_storage = self.specs_world.read_storage::<Weapon>();

        graphics::set_color(ctx, graphics::Color::new(1.0, 0.0, 1.0, 1.0))?;
        for weapon in (&weapon_storage).join() {
            if let Some(collision_rects) = &weapon.collision_points {
                for rect in collision_rects {
                    graphics::rectangle(
                        ctx,
                        graphics::DrawMode::Line(1.0),
                        graphics::Rect {
                            x: (rect.bounding.x * 3) as f32,
                            y: (rect.bounding.y * 3) as f32,
                            w: rect.bounding.w as f32 * 3.0,
                            h: rect.bounding.h as f32 * 3.0,
                        },
                    )?;
                    for point in &rect.points {
                        graphics::rectangle(
                            ctx,
                            graphics::DrawMode::Line(1.0),
                            graphics::Rect {
                                x: (point.x as i32 * 3) as f32,
                                y: (point.y as i32 * 3) as f32,
                                w: 3.0,
                                h: 3.0,
                            },
                        )?;
                    }
                }
            }
        }
        graphics::set_color(ctx, graphics::Color::new(1.0, 1.0, 1.0, 1.0))?;

        //let banner = &self.rects[73];
        //self.batch.add(graphics::DrawParam {
        //    src: graphics::Rect {
        //        x: banner.x as f32 / 512.0,
        //        y: banner.y as f32 / 512.0,
        //        w: banner.w as f32 / 512.0,
        //        h: banner.h as f32 / 512.0,
        //    },
        //    dest: graphics::Point2::new(5.0, 20.0),
        //    //scale: graphics::Point2::new(3.0, 3.0),
        //    ..Default::default()
        //});

        //let copyright = &self.rects[74];
        //self.batch.add(graphics::DrawParam {
        //    src: graphics::Rect {
        //        x: copyright.x as f32 / 512.0,
        //        y: copyright.y as f32 / 512.0,
        //        w: copyright.w as f32 / 512.0,
        //        h: copyright.h as f32 / 512.0,
        //    },
        //    dest: graphics::Point2::new(22.0, 181.0),
        //    //scale: graphics::Point2::new(3.0, 3.0),
        //    ..Default::default()
        //});

        //let rights = &self.rects[75];
        //self.batch.add(graphics::DrawParam {
        //    src: graphics::Rect {
        //        x: rights.x as f32 / 512.0,
        //        y: rights.y as f32 / 512.0,
        //        w: rights.w as f32 / 512.0,
        //        h: rights.h as f32 / 512.0,
        //    },
        //    dest: graphics::Point2::new(110.0, 190.0),
        //    //scale: graphics::Point2::new(3.0, 3.0),
        //    ..Default::default()
        //});
        //graphics::draw_ex(
        //    ctx,
        //    &self.batch,
        //    graphics::DrawParam {
        //        dest: dest_point,
        //        scale: graphics::Point2::new(3.0, 3.0),
        //        ..Default::default()
        //    },
        //)?;
        //self.batch.clear();
        // graphics::present(ctx);

        // println!("Delta frame time: {:?} ", timer::get_delta(ctx));
        // println!("Average FPS: {}", timer::get_fps(ctx));
        // timer::sleep(Duration::from_millis(50));
        //timer::sleep(Duration::from_millis(100));
        //timer::sleep(Duration::from_millis(109));
        Ok(())
    }

    fn name(&self) -> &str {
        "Encounter"
    }

    fn input(&mut self, _gameworld: &mut Game, _event: input::InputEvent, _started: bool) {
        // gameworld.input.update_effect(event, started);
    }
}
