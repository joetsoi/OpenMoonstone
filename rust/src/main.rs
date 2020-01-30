#![warn(rust_2018_idioms)]

use std::iter::repeat;
use std::time::Duration;
use std::{env, path};

use ggez::conf;
use ggez::event;
use ggez::filesystem;
use ggez::graphics;
use ggez::timer;
use ggez::{Context, ContextBuilder, GameResult};
// use image::RgbaImage;

use warmy::SimpleKey;

use openmoonstone::game::Game;
use openmoonstone::input;
use openmoonstone::objects::TextureAtlas;
use openmoonstone::palette::PaletteSwaps;
use openmoonstone::piv::PivImage;
use openmoonstone::piv::{extract_palette, Colour};
use openmoonstone::scenes;
use openmoonstone::scenes::transition::FadeStyle;
use openmoonstone::scenes::{FSceneStack, Fade, MainMenuScene, MainScene, SelectKnight};

struct MainState {
    input_binding: input::InputBinding,
    scene_stack: FSceneStack,
}

impl event::EventHandler for MainState {
    fn update(&mut self, ctx: &mut Context) -> GameResult<()> {
        const MAX_UPDATES_PER_FRAME: u32 = 1;
        // see https://docs.rs/ggez/0.4.4/ggez/timer/fn.check_update_time.html
        // we don't want our while loop to allow unbounded number of ticks
        // in between draw calls, ideally we'd like it to be 1-1.
        //
        // Limiting the number of updates means that when the scene is first
        // loaded we don't suddenly call update loads of times at once.
        // causing knights to zip across the screen if the move button is held.
        // TODO look into passing delta time to scene_stack.update()
        // this might mean we can go back to the recommended loop
        // TODO allow this to be configurable so if people need frame skip as they
        // are running this on a potato then they can.
        let mut ticks = 0;

        // https://en.wikibooks.org/wiki/X86_Assembly/Programmable_Interval_Timer
        const DOS_PIT_FREQUENCY: u32 = 1_193_182; // hz
        const FREQUENCY_DIVISOR: u32 = 21_845; // taken from DOS version of moonstone
        const ONE_SECOND: u32 = 1000; // ms
        const DESIRED_FPS: u32 = ONE_SECOND / (DOS_PIT_FREQUENCY / FREQUENCY_DIVISOR);
        while timer::check_update_time(ctx, DESIRED_FPS) {
            if ticks < MAX_UPDATES_PER_FRAME {
                self.scene_stack.world.input.update(1.0);
                self.scene_stack.update(ctx);
            }
            ticks += 1;
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        self.scene_stack.draw(ctx);
        graphics::present(ctx);
        timer::sleep(Duration::from_millis(50));
        Ok(())
    }

    fn key_down_event(
        &mut self,
        ctx: &mut Context,
        keycode: event::KeyCode,
        keymods: event::KeyMods,
        repeat: bool,
    ) {
        self.scene_stack
            .input(input::InputEvent::Key(keycode), true);
        if let Some(ev) = self.input_binding.resolve(keycode) {
            self.scene_stack.input(input::InputEvent::Binded(ev), true);
            self.scene_stack.world.input.update_effect(ev, true);
        }
    }

    fn key_up_event(
        &mut self,
        ctx: &mut Context,
        keycode: event::KeyCode,
        keymods: event::KeyMods,
    ) {
        if let Some(ev) = self.input_binding.resolve(keycode) {
            self.scene_stack.input(input::InputEvent::Binded(ev), false);
            self.scene_stack.world.input.update_effect(ev, false);
        }
    }
    fn text_input_event(&mut self, _ctx: &mut Context, c: char) {
        self.scene_stack.input(input::InputEvent::Text(c), true);
    }
}

fn main() {
    let mut builder = ContextBuilder::new("openmoonstone", "joetsoi");
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let path = path::PathBuf::from(manifest_dir).join("resources");
        println!("Adding 'resources' path {:?}", path);
        builder = builder.add_resource_path(path);
    }
    let (ctx, event_loop) = &mut builder.build().unwrap();
    println!("{:?}", graphics::screen_coordinates(ctx));
    println!("{:?}", graphics::renderer_info(ctx));
    graphics::set_default_filter(ctx, graphics::FilterMode::Nearest);

    let game = Game::new().expect("failed to initialize game");
    let scale_matrix = graphics::DrawParam::default()
        .scale(game.screen_scale)
        .to_matrix();
    graphics::push_transform(ctx, Some(scale_matrix));
    graphics::apply_transformations(ctx);

    let mut scene_stack = scenes::FSceneStack::new(ctx, game);
    let map = scene_stack
        .world
        .store
        .get::<PivImage>(&SimpleKey::from("map".to_string()), ctx)
        // TODO: fix with ? error syntax
        .expect("error loading wa1");
    // let image = RgbaImage::from_raw(512, 512, map.borrow().to_rgba8_512()).unwrap();
    // image.save("ch.png");

    // let swaps_res = scene_stack.world.store
    //     .get::<PaletteSwaps>(&SimpleKey::from("/palettes.yaml"), ctx)
    //     // TODO: fix with ?
    //     .expect("error loading palette.yaml");
    // let swaps = swaps_res.borrow();
    // let raw_palette = swaps
    //     .0
    //     .get("default")
    //     .expect("failed to fetch default palette");
    // let palette = extract_palette(raw_palette);

    let cmp = scene_stack
        .world
        .store
        .get::<TextureAtlas>(&SimpleKey::from("mi.c".to_string()), ctx)
        // TODO: fix with ? error syntax
        .expect("error loading wa1");

    let mut palette = map.borrow().palette.to_vec();
    if palette.len() == 16 {
        palette.extend(
            repeat(Colour {
                r: 0,
                g: 0,
                b: 0,
                a: 0,
            })
            .take(16),
        );
    }
    // let image = RgbaImage::from_raw(2048, 2048, cmp.borrow().image.to_rgba8(&map.borrow().palette)).unwrap();
    // // let image = RgbaImage::from_raw(256, 256, cmp.borrow().image.to_rgba8(&palette)).unwrap();
    // image.save("mi.c.png");
    // println!("{:x?}", map.borrow().raw_palette);
    // panic!("wee");

    let main_scene = MainScene::new();
    scene_stack.push(Box::new(main_scene));

    let menu = MainMenuScene::new(ctx, &mut scene_stack.world.store).unwrap();
    scene_stack.push(Box::new(menu));

    // let fade_in = Fade::new(274, 1, FadeStyle::In);
    // scene_stack.push(Box::new(fade_in));

    // let sk = SelectKnight::new(ctx, &mut scene_stack.world.store).unwrap();
    // scene_stack.push(Box::new(sk));

    // let map = scenes::MapScene::new(ctx, &mut scene_stack.world.store, "map").unwrap();
    // scene_stack.push(Box::new(map));

    let mut state = MainState {
        scene_stack,
        input_binding: input::create_input_binding(),
    };
    event::run(ctx, event_loop, &mut state).unwrap();
}
