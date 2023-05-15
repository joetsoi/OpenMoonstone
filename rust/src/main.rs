#![warn(rust_2018_idioms)]
use std::io::Read;
use std::{env, path};

use color_eyre::{self, Result};
use ggez::event;
use ggez::input::keyboard;

use files::terrain::Background;
use files::{Files, TerrainFile};
use piv::PivImage;
use ron;

mod animation;
mod assets;
mod combat;
mod components;
mod files;
mod game;
mod input;
mod input_binding;
mod lz77;
mod objects;
mod piv;
mod rect;
mod scenes;
mod scenestack;

fn fps_for_scene(scene_name: &str) -> u32 {
    // https://en.wikibooks.org/wiki/X86_Assembly/Programmable_Interval_Timer
    const DOS_PIT_FREQUENCY: u32 = 1_193_182; // hz
    const FREQUENCY_DIVISOR: u32 = 21_845; // taken from DOS version of moonstone
    const ONE_SECOND: u32 = 1000; // ms
    const ENCOUNTER_FPS: u32 = ONE_SECOND / (DOS_PIT_FREQUENCY / FREQUENCY_DIVISOR);
    match scene_name {
        "Encounter" => ENCOUNTER_FPS,
        _ => 30,
    }
}

struct MainState {
    input_binding: input::InputBinding,
    scene_stack: scenes::FSceneStack,
}

impl event::EventHandler for MainState {
    fn update(&mut self, ctx: &mut ggez::Context) -> ggez::GameResult<()> {
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

        let desired_fps: u32 = fps_for_scene(self.scene_stack.current().name());

        while ctx.time.check_update_time(desired_fps) {
            if ticks < MAX_UPDATES_PER_FRAME {
                self.scene_stack.world.input.update(1.0);
                self.scene_stack.update(ctx);
            }
            ticks += 1;
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut ggez::Context) -> ggez::GameResult<()> {
        self.scene_stack.draw(ctx);
        Ok(())
    }

    fn key_down_event(
        &mut self,
        _ctx: &mut ggez::Context,
        key_input: keyboard::KeyInput,
        _repeat: bool,
    ) -> ggez::GameResult {
        if let Some(keycode) = key_input.keycode {
            self.scene_stack
                .input(input::InputEvent::Key(keycode), true);
            if let Some(ev) = self.input_binding.resolve(keycode) {
                self.scene_stack.input(input::InputEvent::Binded(ev), true);
                self.scene_stack.world.input.update_effect(ev, true);
            }
        }
        Ok(())
    }

    fn key_up_event(
        &mut self,
        _ctx: &mut ggez::Context,
        key_input: keyboard::KeyInput,
    ) -> ggez::GameResult {
        if let Some(keycode) = key_input.keycode {
            self.scene_stack
                .input(input::InputEvent::Key(keycode), true);
            if let Some(ev) = self.input_binding.resolve(keycode) {
                self.scene_stack.input(input::InputEvent::Binded(ev), false);
                self.scene_stack.world.input.update_effect(ev, false);
            }
        }
        Ok(())
    }
}

fn load_assets(ctx: &mut ggez::Context, assets: &mut assets::Assets) {
    assets.load_scene(ctx, "wab1");
    assets.load_scene(ctx, "wa1");
    assets.load_terrain(ctx, "wa1.t");
    assets.load_texture_atlas(ctx, "kn1.ob");
    assets.load_texture_atlas(ctx, "kn2.ob");
    assets.load_texture_atlas(ctx, "kn3.ob");
    assets.load_texture_atlas(ctx, "kn4.ob");
    assets.load_collide_hit(ctx);
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let game_id = "openmoonstone";
    let mut builder = ggez::ContextBuilder::new(game_id, game_id);
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let path = path::PathBuf::from(manifest_dir).join("resources");
        println!("Adding 'resources' path {:?}", path);
        builder = builder.add_resource_path(path);
    }
    let (mut ctx, event_loop) = builder.build()?;

    let game = game::Game::new(&mut ctx);
    let mut scene_stack = scenes::FSceneStack::new(&ctx, game);
    load_assets(&mut ctx, &mut scene_stack.world.assets);
    let encounter_builder = scenes::EncounterBuilder::new("wab1", "wa1.t");
    let encounter_scene = encounter_builder.build(&mut ctx, &mut scene_stack.world.assets)?;
    scene_stack.push(Box::new(encounter_scene));

    let state = MainState {
        scene_stack,
        input_binding: input::create_input_binding(),
    };
    event::run(ctx, event_loop, state);
}
