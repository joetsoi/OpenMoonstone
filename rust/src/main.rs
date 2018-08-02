#![feature(rust_2018_preview)]
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
use image::{ImageBuffer, RgbaImage};
use specs::world::Builder;
use specs::{world, Entities};
use specs::{Dispatcher, DispatcherBuilder, Join, RunNow, World};
use warmy::{LogicalKey, Store, StoreOpt};

use openmoonstone::animation::{Image, Sprite};
use openmoonstone::combat::components::{
    AnimationState, Controller, Direction, Draw, Position, WalkingState,
};
use openmoonstone::combat::systems::{Animation, Movement, Renderer};
use openmoonstone::input;
use openmoonstone::objects::{Rect, TextureAtlas};
use openmoonstone::piv::{Colour, PivImage};

struct MainState<'a> {
    dispatcher: Dispatcher<'a, 'a>,
    palette: Vec<Colour>,
    image: graphics::Image,
    batch: graphics::spritebatch::SpriteBatch,
    rects: Vec<Rect>,
    encounter: World,
    store: Store<Context>,

    images: HashMap<String, graphics::Image>,
    batches: HashMap<String, graphics::spritebatch::SpriteBatch>,
    batch_order: Vec<String>,

    input: input::InputState,
    input_binding: input::InputBinding,

    knight_id: world::Index,
}

impl MainState<'a> {
    fn update_controllers(&mut self) {
        let entities = self.encounter.entities();
        let mut controllers = self.encounter.write_storage::<Controller>();
        for (e, controller) in (&*entities, &mut controllers).join() {
            if e.id() == self.knight_id {
                controller.x = self.input.get_axis_raw(input::Axis::Horz) as i32;
                controller.y = self.input.get_axis_raw(input::Axis::Vert) as i32;
                controller.fire = self.input.get_button_down(input::Button::Fire);
            }
        }
    }

    fn update_images(&mut self, ctx: &mut Context) {
        let mut draw_storage = self.encounter.write_storage::<Draw>();
        let animation_storage = self.encounter.read_storage::<AnimationState>();
        let walking_storage = self.encounter.read_storage::<WalkingState>();

        let sprite = self
            .store
            .get::<_, Sprite>(&LogicalKey::new("/knight.yaml"), ctx)
            .unwrap();
        for (draw, animation_state, walking_state) in
            (&mut draw_storage, &animation_storage, &walking_storage).join()
        {
            draw.frame =
                sprite.borrow().animations["walk"][animation_state.frame_number as usize].clone();
            draw.direction = walking_state.direction;
        }
    }
}

impl event::EventHandler for MainState<'a> {
    fn update(&mut self, ctx: &mut Context) -> GameResult<()> {
        const DESIRED_FPS: u32 = 1000 / (1193182 / 21845 * 2);
        while timer::check_update_time(ctx, DESIRED_FPS) {
            let delta = timer::get_delta(ctx);
            self.input
                .update(delta.as_secs() as f32 + delta.subsec_millis() as f32 / 1000.0);
            self.update_controllers();
            self.dispatcher.dispatch_par(&self.encounter.res);
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        self.dispatcher.dispatch_thread_local(&self.encounter.res);
        graphics::set_background_color(ctx, Color::from((0, 0, 0, 255)));
        graphics::clear(ctx);

        let dest_point = graphics::Point2::new(0.0, 0.0);
        graphics::draw_ex(
            ctx,
            &self.image,
            graphics::DrawParam {
                dest: dest_point,
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;
        //self.systems.renderer.run_now(&self.encounter.res, ctx: Context);
        //let mut batches: HashMap<String, graphics::spritebatch::SpriteBatch> = HashMap::new();
        //let mut batch_order: Vec<String> = vec![];
        self.update_images(ctx);
        let position_storage = self.encounter.read_storage::<Position>();
        let draw_storage = self.encounter.read_storage::<Draw>();
        for (position, draw) in (&position_storage, &draw_storage).join() {
            for image in &draw.frame.images {
                let atlas = self
                    .store
                    .get::<_, TextureAtlas>(&LogicalKey::new(image.sheet.as_str()), ctx)
                    .unwrap();
                let mut batch = match self.batches.entry(image.sheet.clone()) {
                    Occupied(entry) => entry.into_mut(),
                    Vacant(entry) => {
                        self.batch_order.push(image.sheet.clone());
                        let atlas_dimension = atlas.borrow().image.width as u32;
                        let image = match (self.images.entry(image.sheet.clone())) {
                            Occupied(i) => i.into_mut(),
                            Vacant(i) => i.insert(
                                graphics::Image::from_rgba8(
                                    ctx,
                                    atlas_dimension as u16,
                                    atlas_dimension as u16,
                                    &atlas.borrow().image.to_rgba8(&self.palette),
                                ).unwrap(),
                            ),
                        };
                        entry.insert(SpriteBatch::new(image.clone()))
                    }
                };

                let rect = atlas.borrow().rects[image.image];
                let texture_size = atlas.borrow().image.width as f32;
                batch.add(graphics::DrawParam {
                    src: graphics::Rect {
                        x: rect.x as f32 / texture_size,
                        y: rect.y as f32 / texture_size,
                        w: rect.w as f32 / texture_size,
                        h: rect.h as f32 / texture_size,
                    },
                    dest: graphics::Point2::new(
                        (position.x as i32 + (draw.direction as i32 * image.x)) as f32,
                        (position.y as i32 + image.y) as f32,
                    ),
                    scale: graphics::Point2::new((draw.direction as i32) as f32, 1.0),
                    ..Default::default()
                });
            }
        }
        for batch_name in &self.batch_order {
            let mut batch = self.batches.get_mut(batch_name).unwrap();
            graphics::draw_ex(
                ctx,
                batch,
                graphics::DrawParam {
                    dest: dest_point,
                    scale: graphics::Point2::new(3.0, 3.0),
                    ..Default::default()
                },
            )?;
            batch.clear();
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
        timer::sleep(Duration::from_millis(109));
        Ok(())
    }

    fn key_down_event(
        &mut self,
        _ctx: &mut Context,
        keycode: event::Keycode,
        _keymod: event::Mod,
        _repeat: bool,
    ) {
        if let Some(ev) = self.input_binding.resolve(keycode) {
            self.input.update_effect(ev, true);
        }
    }

    fn key_up_event(
        &mut self,
        _ctx: &mut Context,
        keycode: event::Keycode,
        _keymod: event::Mod,
        _repeat: bool,
    ) {
        if let Some(ev) = self.input_binding.resolve(keycode) {
            self.input.update_effect(ev, false);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let ob = &args[2];

    let c = conf::Conf::new();
    let ctx = &mut Context::load_from_conf("openmoonstone", "joetsoi", c).unwrap();
    graphics::set_default_filter(ctx, graphics::FilterMode::Nearest);

    let mut store: Store<Context> = Store::new(StoreOpt::default()).expect("store creation");
    let piv = store
        .get::<_, PivImage>(&LogicalKey::new(filename), ctx)
        .unwrap();

    let atlas = store
        .get::<_, TextureAtlas>(&LogicalKey::new(ob), ctx)
        .unwrap();

    let sprite = store
        .get::<_, Sprite>(&LogicalKey::new("/knight.yaml"), ctx)
        .unwrap();

    let atlas_dimension = atlas.borrow().image.width as u32;
    // let mut a: RgbaImage = ImageBuffer::from_raw(
    //     atlas_dimension,
    //     atlas_dimension,
    //     atlas.borrow().image.to_rgba8(&*piv.borrow().palette),
    // ).unwrap();
    // a.save("test.png");

    let background = graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8()).unwrap();
    let image = graphics::Image::from_rgba8(
        ctx,
        atlas_dimension as u16,
        atlas_dimension as u16,
        &atlas.borrow().image.to_rgba8(&*piv.borrow().palette),
    ).unwrap();
    //let test = image.clone();
    let batch = graphics::spritebatch::SpriteBatch::new(image);

    // let im1 = &ob.images[0];
    // let test = Image::from_rgba8(
    //     ctx,
    //     im1.width as u16,
    //     im1.height as u16,
    //     &im1.to_rgba8(&piv.palette),
    // ).unwrap();

    let mut encounter = World::new();
    encounter.register::<AnimationState>();
    encounter.register::<Controller>();
    encounter.register::<Draw>();
    encounter.register::<Position>();
    encounter.register::<WalkingState>();
    let knight = encounter
        .create_entity()
        .with(Controller {
            x: 0,
            y: 0,
            fire: false,
        })
        .with(Position { x: 100, y: 150 })
        .with(Draw {
            frame: sprite.borrow().animations["walk"][0].clone(),
            direction: Direction::default(),
        })
        .with(WalkingState {
            ..Default::default()
        })
        .with(AnimationState {
            ..Default::default()
        })
        .build();

    let mut dispatcher = DispatcherBuilder::new()
        .with(Movement, "movement", &[])
        .with(Animation, "animation", &["movement"])
        // .with_thread_local(Renderer {
        //     store: Store::new(StoreOpt::default()).expect("store creation"),
        // })
        .build();

    let mut state = MainState {
        dispatcher: dispatcher,
        palette: piv.borrow().palette.to_vec(),
        image: background,
        batch: batch,
        rects: atlas.borrow().rects.clone(),
        encounter: encounter,
        store: store,
        images: HashMap::new(),
        batches: HashMap::new(),
        batch_order: vec![],
        input: input::InputState::new(),
        input_binding: input::create_input_binding(),
        knight_id: knight.id(),
    };

    event::run(ctx, &mut state).unwrap();
}
