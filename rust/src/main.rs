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

use openmoonstone::animation::{ImageType, Sprite};
use openmoonstone::combat::components::{
    AnimationState, Body, Collided, Controller, Draw, Facing, Health, Intent, Position, State,
    Velocity, WalkingState, Weapon,
};
use openmoonstone::combat::systems::{
    ActionSystem, Animation, CheckCollisions, Commander, ConfirmVelocity, EntityDeath,
    EntityEntityCollision, Movement, ResolveCollisions, RestrictMovementToBoundary, StateUpdater,
    UpdateBoundingBoxes, UpdateImage, VelocitySystem,
};
use openmoonstone::files::collide::CollisionBoxes;
use openmoonstone::game::Game;
use openmoonstone::input;
use openmoonstone::objects::TextureAtlas;
use openmoonstone::piv::{Colour, PivImage};
use openmoonstone::scenes;
use openmoonstone::scenes::encounter::EncounterScene;
use openmoonstone::scenes::FSceneStack;

struct MainState {
    input_binding: input::InputBinding,
    scene_stack: FSceneStack,
    images: HashMap<String, graphics::Image>,
    batches: HashMap<String, graphics::spritebatch::SpriteBatch>,
}

impl event::EventHandler for MainState {
    fn update(&mut self, ctx: &mut Context) -> GameResult<()> {
        const DESIRED_FPS: u32 = 1000 / (1193182 / 21845 * 2);
        // const DESIRED_FPS: u32 = 1;
        while timer::check_update_time(ctx, DESIRED_FPS) {
            let delta = timer::get_delta(ctx);
            self.scene_stack
                .world
                .input
                .update(delta.as_secs() as f32 + delta.subsec_millis() as f32 / 1000.0);
            self.scene_stack.update();
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        self.scene_stack.draw(ctx);
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
            self.scene_stack.input(ev, true);
            self.scene_stack.world.input.update_effect(ev, true);
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
            self.scene_stack.input(ev, false);
            self.scene_stack.world.input.update_effect(ev, false);
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

    let mut game = Game::new(ctx).expect("failed to initialize game");
    // let piv = game
    //     .store
    //     .get::<_, PivImage>(&LogicalKey::new(filename), ctx)
    //     .unwrap();

    // let atlas = store
    //     .get::<_, TextureAtlas>(&LogicalKey::new(ob), ctx)
    //     .unwrap();

    // let sprite = game
    //     .store
    //     .get::<_, Sprite>(&LogicalKey::new("/knight.yaml"), ctx)
    //     .unwrap();

    // let collide_hit = game
    //     .store
    //     .get::<_, CollisionBoxes>(&LogicalKey::new("collide"), ctx)
    //     .unwrap();
    // game.world.add_resource(collide_hit.borrow().clone());

    //let atlas_dimension = atlas.borrow().image.width as u32;
    // let mut a: RgbaImage = ImageBuffer::from_raw(
    //     atlas_dimension,
    //     atlas_dimension,
    //     atlas.borrow().image.to_rgba8(&*piv.borrow().palette),
    // ).unwrap();
    // a.save("test.png");

    //let background = graphics::Image::from_rgba8(ctx, 320, 200, &*piv.borrow().to_rgba8()).unwrap();
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

    // let knight = game
    //     .world
    //     .create_entity()
    //     .with(Controller {
    //         x: 0,
    //         y: 0,
    //         fire: false,
    //     })
    //     .with(Position { x: 100, y: 100 })
    //     .with(Health {
    //         ..Default::default()
    //     })
    //     .with(Draw {
    //         frame: sprite.borrow().animations["walk"].frames[0].clone(),
    //         animation: "walk".to_string(),
    //         resource_name: "knight".to_string(),
    //         direction: Facing::default(),
    //     })
    //     .with(Intent {
    //         ..Default::default()
    //     })
    //     .with(WalkingState {
    //         ..Default::default()
    //     })
    //     .with(Velocity {
    //         ..Default::default()
    //     })
    //     .with(AnimationState {
    //         ..Default::default()
    //     })
    //     .with(State {
    //         ..Default::default()
    //     })
    //     .with(Body {
    //         ..Default::default()
    //     })
    //     .with(Weapon {
    //         ..Default::default()
    //     })
    //     .build();

    // let player_2 = game
    //     .world
    //     .create_entity()
    //     .with(Controller {
    //         x: 0,
    //         y: 0,
    //         fire: false,
    //     })
    //     .with(Position { x: 200, y: 100 })
    //     .with(Health {
    //         ..Default::default()
    //     })
    //     .with(Draw {
    //         frame: sprite.borrow().animations["walk"].frames[0].clone(),
    //         animation: "walk".to_string(),
    //         resource_name: "knight".to_string(),
    //         direction: Facing::default(),
    //     })
    //     .with(Intent {
    //         ..Default::default()
    //     })
    //     .with(WalkingState {
    //         ..Default::default()
    //     })
    //     .with(Velocity {
    //         ..Default::default()
    //     })
    //     .with(AnimationState {
    //         ..Default::default()
    //     })
    //     .with(State {
    //         ..Default::default()
    //     })
    //     .with(Body {
    //         ..Default::default()
    //     })
    //     .with(Weapon {
    //         ..Default::default()
    //     })
    //     .build();

    //let dispatcher = DispatcherBuilder::new()
    //    .with(Commander, "commander", &[])
    //    .with(ActionSystem, "action", &["commander"])
    //    .with(EntityDeath, "entity_death", &["action"])
    //    .with(VelocitySystem, "velocity", &["commander"])
    //    .with(EntityEntityCollision, "entity_collision", &["velocity"])
    //    .with(
    //        RestrictMovementToBoundary,
    //        "restrict_movement_to_boundary",
    //        &["velocity"],
    //    )
    //    .with(
    //        ConfirmVelocity,
    //        "confirm_velocity",
    //        &["restrict_movement_to_boundary", "entity_collision"],
    //    )
    //    .with(Movement, "movement", &["confirm_velocity"])
    //    .with(Animation, "animation", &["movement"])
    //    //.with(StateUpdater, "state_updater", &["animation"])
    //    .with(UpdateImage, "update_image", &["animation"])
    //    .with(
    //        UpdateBoundingBoxes,
    //        "update_bounding_boxes",
    //        &["update_image"],
    //    )
    //    .with(
    //        CheckCollisions,
    //        "check_collisions",
    //        &["update_bounding_boxes"],
    //    )
    //    .with(
    //        ResolveCollisions,
    //        "resolve_collisions",
    //        &["check_collisions"],
    //    )
    //    .with(StateUpdater, "state_updater", &["resolve_collisions"])
    //    // .with_thread_local(Renderer {
    //    //     store: Store::new(StoreOpt::default()).expect("store creation"),
    //    // })
    //    .build();

    let mut scene_stack = scenes::FSceneStack::new(ctx, game);
    println!("stack ");
    let encounter_scene =
        EncounterScene::new(ctx, &mut scene_stack.world.store, &["knight"], filename)
            .expect("failed to init game");
    scene_stack.push(Box::new(encounter_scene));
    println!("built encounter");

    let mut state = MainState {
        scene_stack,
        input_binding: input::create_input_binding(),
        images: HashMap::new(),
        batches: HashMap::new(),
    };

    event::run(ctx, &mut state).unwrap();;
}
