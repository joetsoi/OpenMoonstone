#![warn(rust_2018_idioms)]

use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::env;
use std::time::Duration;

use ggez::conf;
use ggez::event;
use ggez::graphics;
use ggez::graphics::spritebatch::SpriteBatch;
use ggez::graphics::Color;
use ggez::timer;
use ggez::{Context, GameResult};
//use image::{ImageBuffer, RgbaImage};
use specs::world;
use specs::world::Builder;
use specs::{Dispatcher, DispatcherBuilder, Join, World};
use warmy::{LogicalKey, Store, StoreOpt};

use openmoonstone::animation::Sprite;
use openmoonstone::combat::components::{
    AnimationState, Body, Controller, Draw, Facing, Intent, Position, State, TouchingBoundary,
    Velocity, WalkingState, Weapon,
};
use openmoonstone::combat::systems::{
    ActionSystem, Animation, Boundary, Commander, Movement, StateUpdater, UpdateBoundingBoxes,
    UpdateImage, VelocitySystem,
};
use openmoonstone::files::collide::CollisionBoxes;
use openmoonstone::game::Game;
use openmoonstone::input;
//use openmoonstone::objects::{Rect, TextureAtlas};
use openmoonstone::objects::TextureAtlas;
use openmoonstone::piv::{Colour, PivImage};

struct MainState<'a> {
    dispatcher: Dispatcher<'a, 'a>,
    palette: Vec<Colour>,
    image: graphics::Image,
    //batch: graphics::spritebatch::SpriteBatch,
    //rects: Vec<Rect>,
    game: Game,

    images: HashMap<String, graphics::Image>,
    batches: HashMap<String, graphics::spritebatch::SpriteBatch>,

    knight_id: world::Index,
    player_2: world::Index,
}

impl<'a> MainState<'a> {
    fn update_controllers(&mut self) {
        let entities = self.game.world.entities();
        let mut controllers = self.game.world.write_storage::<Controller>();
        for (e, controller) in (&*entities, &mut controllers).join() {
            if e.id() == self.knight_id {
                controller.x = self.game.input.get_axis_raw(input::Axis::Horz1) as i32;
                controller.y = self.game.input.get_axis_raw(input::Axis::Vert1) as i32;
                controller.fire = self.game.input.get_button_down(input::Button::Fire1);
            } else if e.id() == self.player_2 {
                controller.x = self.game.input.get_axis_raw(input::Axis::Horz2) as i32;
                controller.y = self.game.input.get_axis_raw(input::Axis::Vert2) as i32;
                controller.fire = self.game.input.get_button_down(input::Button::Fire2);
            }
        }
    }
}

impl<'a> event::EventHandler for MainState<'a> {
    fn update(&mut self, ctx: &mut Context) -> GameResult<()> {
        //const DESIRED_FPS: u32 = 1000 / (1193182 / 21845 * 2);
        const DESIRED_FPS: u32 = 1;
        while timer::check_update_time(ctx, DESIRED_FPS) {
            let delta = timer::get_delta(ctx);
            self.game
                .input
                .update(delta.as_secs() as f32 + delta.subsec_millis() as f32 / 1000.0);
            self.update_controllers();
            self.dispatcher.dispatch_par(&self.game.world.res);
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        //self.dispatcher.dispatch_thread_local(&self.game.world.res);
        graphics::set_background_color(ctx, Color::from((0, 0, 0, 255)));
        graphics::clear(ctx);

        let screen_origin = graphics::Point2::new(0.0, 0.0);
        // draw background
        graphics::draw_ex(
            ctx,
            &self.image,
            graphics::DrawParam {
                dest: screen_origin,
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;
        //self.systems.renderer.run_now(&self.game.world.res, ctx: Context);
        //let mut batches: HashMap<String, graphics::spritebatch::SpriteBatch> = HashMap::new();
        let mut batch_order: Vec<String> = vec![];
        let position_storage = self.game.world.read_storage::<Position>();
        let draw_storage = self.game.world.read_storage::<Draw>();

        let mut storage = (&position_storage, &draw_storage)
            .join()
            .collect::<Vec<_>>();
        storage.sort_by(|&a, &b| a.0.y.cmp(&b.0.y));

        for (position, draw) in storage {
            for image in &draw.frame.images {
                let atlas = self
                    .game
                    .store
                    .get::<_, TextureAtlas>(&LogicalKey::new(image.sheet.as_str()), ctx)
                    .unwrap();

                let atlas_dimension = atlas.borrow().image.width as u32;
                let ggez_image = match self.images.entry(image.sheet.clone()) {
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

                let rect = atlas.borrow().rects[image.image];
                let texture_size = atlas.borrow().image.width as f32;
                graphics::draw_ex(
                    ctx,
                    ggez_image,
                    graphics::DrawParam {
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
                    },
                )?;
            }
        }

        let body_storage = self.game.world.read_storage::<Body>();

        let mut storage = (&position_storage, &body_storage)
            .join()
            .collect::<Vec<_>>();

        // graphics::set_color(ctx, graphics::Color::new(1.0, 1.0, 1.0, 1.0))?;
        // for (position, body) in storage {
        //     if let Some(boxes) = &body.collision_boxes {
        //         for collision_box in boxes {
        //             graphics::rectangle(ctx, graphics::DrawMode::Line(1.0), graphics::Rect {
        //                 x: (position.x as i32 + collision_box.x) as f32 * 3.0,
        //                 y: (position.y as i32 + collision_box.y) as f32 * 3.0,
        //                 w: collision_box.w as f32 * 3.0,
        //                 h: collision_box.h as f32 * 3.0,
        //             })?;

        //         }
        //     }
        // }

        let weapon_storage = self.game.world.read_storage::<Weapon>();

        let mut storage = (&position_storage, &weapon_storage)
            .join()
            .collect::<Vec<_>>();

        graphics::set_color(ctx, graphics::Color::new(1.0, 1.0, 1.0, 1.0))?;
        for (position, weapon) in storage {
            if let Some(collision_rects) = &weapon.collision_points {
                for rect in collision_rects {
                    graphics::rectangle(
                        ctx,
                        graphics::DrawMode::Line(1.0),
                        graphics::Rect {
                            x: ((position.x as i32 + rect.bounding.x) * 3) as f32,
                            y: ((position.y as i32 + rect.bounding.y) * 3) as f32,
                            w: rect.bounding.w as f32 * 3.0,
                            h: rect.bounding.h as f32 * 3.0,
                        },
                    )?;
                    for point in &rect.points {
                        graphics::rectangle(
                            ctx,
                            graphics::DrawMode::Line(1.0),
                            graphics::Rect {
                                x: ((position.x as i32 + rect.bounding.x + point.x as i32) * 3)
                                    as f32,
                                y: ((position.y as i32 + rect.bounding.y + point.y as i32) * 3)
                                    as f32,
                                w: 3.0,
                                h: 3.0,
                            },
                        )?;
                    }
                }
            }
        }

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
        graphics::present(ctx);

        // println!("Delta frame time: {:?} ", timer::get_delta(ctx));
        // println!("Average FPS: {}", timer::get_fps(ctx));
        //timer::sleep(Duration::from_millis(55));
        timer::sleep(Duration::from_millis(100));
        //timer::sleep(Duration::from_millis(109));
        Ok(())
    }

    fn key_down_event(
        &mut self,
        _ctx: &mut Context,
        keycode: event::Keycode,
        _keymod: event::Mod,
        _repeat: bool,
    ) {
        if let Some(ev) = self.game.input_binding.resolve(keycode) {
            self.game.input.update_effect(ev, true);
        }
    }

    fn key_up_event(
        &mut self,
        _ctx: &mut Context,
        keycode: event::Keycode,
        _keymod: event::Mod,
        _repeat: bool,
    ) {
        if let Some(ev) = self.game.input_binding.resolve(keycode) {
            self.game.input.update_effect(ev, false);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    //let ob = &args[2];

    let c = conf::Conf::new();
    let ctx = &mut Context::load_from_conf("openmoonstone", "joetsoi", c).unwrap();
    graphics::set_default_filter(ctx, graphics::FilterMode::Nearest);

    let mut game = Game::new(ctx, &["knight"]).expect("failed to initialize game");
    let piv = game
        .store
        .get::<_, PivImage>(&LogicalKey::new(filename), ctx)
        .unwrap();

    // let atlas = store
    //     .get::<_, TextureAtlas>(&LogicalKey::new(ob), ctx)
    //     .unwrap();

    let sprite = game
        .store
        .get::<_, Sprite>(&LogicalKey::new("/knight.yaml"), ctx)
        .unwrap();

    let collide_hit = game
        .store
        .get::<_, CollisionBoxes>(&LogicalKey::new("collide"), ctx)
        .unwrap();
    game.world.add_resource(collide_hit.borrow().clone());

    //let atlas_dimension = atlas.borrow().image.width as u32;
    // let mut a: RgbaImage = ImageBuffer::from_raw(
    //     atlas_dimension,
    //     atlas_dimension,
    //     atlas.borrow().image.to_rgba8(&*piv.borrow().palette),
    // ).unwrap();
    // a.save("test.png");

    let background = graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8()).unwrap();
    // let image = graphics::Image::from_rgba8(
    //     ctx,
    //     atlas_dimension as u16,
    //     atlas_dimension as u16,
    //     &atlas.borrow().image.to_rgba8(&*piv.borrow().palette),
    // ).unwrap();
    //let test = image.clone();
    //let batch = graphics::spritebatch::SpriteBatch::new(image);

    // let im1 = &ob.images[0];
    // let test = Image::from_rgba8(
    //     ctx,
    //     im1.width as u16,
    //     im1.height as u16,
    //     &im1.to_rgba8(&piv.palette),
    // ).unwrap();
    //

    let knight = game
        .world
        .create_entity()
        .with(Controller {
            x: 0,
            y: 0,
            fire: false,
        })
        .with(Position { x: 100, y: 100 })
        .with(Draw {
            frame: sprite.borrow().animations["walk"].frames[0].clone(),
            animation: "walk".to_string(),
            resource_name: "knight".to_string(),
            direction: Facing::default(),
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
        .with(TouchingBoundary {
            ..Default::default()
        })
        .with(AnimationState {
            ..Default::default()
        })
        .with(State {
            ..Default::default()
        })
        .with(Body {
            ..Default::default()
        })
        .with(Weapon {
            ..Default::default()
        })
        .build();

    let player_2 = game
        .world
        .create_entity()
        .with(Controller {
            x: 0,
            y: 0,
            fire: false,
        })
        .with(Position { x: 200, y: 100 })
        .with(Draw {
            frame: sprite.borrow().animations["walk"].frames[0].clone(),
            animation: "walk".to_string(),
            resource_name: "knight".to_string(),
            direction: Facing::default(),
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
        .with(TouchingBoundary {
            ..Default::default()
        })
        .with(AnimationState {
            ..Default::default()
        })
        .with(State {
            ..Default::default()
        })
        .with(Body {
            ..Default::default()
        })
        .with(Weapon {
            ..Default::default()
        })
        .build();

    let dispatcher = DispatcherBuilder::new()
        .with(Commander, "commander", &[])
        .with(Boundary, "boundary", &["commander"])
        .with(ActionSystem, "action", &["commander"])
        .with(VelocitySystem, "velocity", &["boundary"])
        .with(Movement, "movement", &["boundary"])
        .with(Animation, "animation", &["movement"])
        .with(StateUpdater, "state_updater", &["animation"])
        .with(UpdateImage, "update_image", &["state_updater"])
        .with(
            UpdateBoundingBoxes,
            "update_bounding_boxes",
            &["update_image"],
        )
        // .with_thread_local(Renderer {
        //     store: Store::new(StoreOpt::default()).expect("store creation"),
        // })
        .build();

    let mut state = MainState {
        game: game,
        dispatcher: dispatcher,
        palette: piv.borrow().palette.to_vec(),
        image: background,
        //batch: batch,
        //rects: atlas.borrow().rects.clone(),
        images: HashMap::new(),
        batches: HashMap::new(),
        knight_id: knight.id(),
        player_2: player_2.id(),
    };

    event::run(ctx, &mut state).unwrap();;
}
