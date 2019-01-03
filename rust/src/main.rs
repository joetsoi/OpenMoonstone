#![warn(rust_2018_idioms)]

use std::env;
use std::time::Duration;

use ggez::conf;
use ggez::event;
use ggez::graphics;
use ggez::timer;
use ggez::{Context, GameResult};
use ggez_goodies::scene::Scene;

use openmoonstone::game::Game;
use openmoonstone::input;
use openmoonstone::scenes;
use openmoonstone::scenes::transition::FadeStyle;
use openmoonstone::scenes::{EncounterScene, FSceneStack, Fade, MainScene, Menu};

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

        const DESIRED_FPS: u32 = 1000 / (1193182 / 21845 * 2);
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

    let c = conf::Conf::new();
    let ctx = &mut Context::load_from_conf("openmoonstone", "joetsoi", c).unwrap();
    graphics::set_default_filter(ctx, graphics::FilterMode::Nearest);

    let game = Game::new().expect("failed to initialize game");
    let mut scene_stack = scenes::FSceneStack::new(ctx, game);

    // let encounter_scene = EncounterScene::new(
    //     ctx,
    //     &mut scene_stack.world.store,
    //     &["knight", "dagger"],
    //     filename,
    // )
    // .expect("failed to init game");
    // scene_stack.push(Box::new(encounter_scene));

    // let fade_in = Fade::new(274, 1, FadeStyle::In);
    // scene_stack.push(Box::new(fade_in));
    // let fade_out = Fade::new(274, 1, FadeStyle::Out);
    // scene_stack.push(Box::new(fade_out));
    let main_scene = MainScene::new();
    scene_stack.push(Box::new(main_scene));

    let menu = Menu::new(ctx, &mut scene_stack.world.store).unwrap();
    scene_stack.push(Box::new(menu));

    let fade_in = Fade::new(274, 1, FadeStyle::In);
    scene_stack.push(Box::new(fade_in));

    //     let fade_in = Fade::new(274, 1, FadeStyle::In);
    //     scene_stack.push(Box::new(fade_in));

    // let c: usize = 3;
    // // let s: Option<Scene<Context, Game>> = (0..c).map(|i| scene_stack.pop()).collect().nth(c);
    // let mut s = None;
    // for i in (0..c) {
    //     s = Some(scene_stack.pop());
    //     println!("{}", s.unwrap().name());
    // }

    let mut state = MainState {
        scene_stack,
        input_binding: input::create_input_binding(),
    };
    event::run(ctx, &mut state).unwrap();;
}
