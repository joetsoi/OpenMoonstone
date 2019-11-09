use std::collections::HashMap;
use std::error::Error;
use std::fmt;

// use failure::{err_msg, Error};
use ggez::nalgebra::{Point2, Vector2};
use ggez::{graphics, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use serde_derive::{Deserialize, Serialize};
use specs::{Dispatcher, DispatcherBuilder, Join, World, WorldExt};
use warmy::{SimpleKey, Store, StoreErrorOr};

use loadable_yaml_macro_derive::LoadableYaml;

// TODO: move these components to common module out of combat
use crate::combat::components::{Controller, Draw, Palette, Position, Velocity};
use crate::combat::systems::Movement;
use crate::error::LoadError;
use crate::game::{Game, SceneState};
use crate::input::{Axis, Button, InputEvent};
use crate::piv::{palette_swap, Colour, PivImage};
use crate::scenes::FSceneSwitch;
use crate::text::Image;

const MAP_ANIMATION_SPEED: u32 = 3;

#[derive(Debug)]
pub enum SceneError {
    Map(StoreErrorOr<MapData, Context, SimpleKey>),
    Piv(StoreErrorOr<PivImage, Context, SimpleKey>),
    Ggez(ggez::error::GameError),
}

impl Error for SceneError {}

impl fmt::Display for SceneError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SceneError::Map(ref err) => err.fmt(f),
            SceneError::Piv(ref err) => err.fmt(f),
            SceneError::Ggez(ref err) => err.fmt(f),
        }
    }
}

impl From<StoreErrorOr<MapData, Context, SimpleKey>> for SceneError {
    fn from(err: StoreErrorOr<MapData, Context, SimpleKey>) -> SceneError {
        SceneError::Map(err)
    }
}

impl From<StoreErrorOr<PivImage, Context, SimpleKey>> for SceneError {
    fn from(err: StoreErrorOr<PivImage, Context, SimpleKey>) -> SceneError {
        SceneError::Piv(err)
    }
}

impl From<ggez::error::GameError> for SceneError {
    fn from(err: ggez::error::GameError) -> SceneError {
        SceneError::Ggez(err)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, LoadableYaml)]
pub struct MapData {
    pub background: String,
    pub lairs: Vec<Image>,
    pub images: HashMap<String, Image>,
}

impl fmt::Display for MapData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MapData {}", self.background)
    }
}

pub struct MapScene<'a> {
    pub specs_world: World,
    pub dispatcher: Dispatcher<'a, 'a>,

    map_data: MapData,
    pub background: Vec<graphics::Image>,
    background_frame: u32,
    current_background_image: usize,
}

impl<'a> MapScene<'a> {
    fn build_world() -> World {
        let mut world = World::new();
        world.register::<Draw>();
        world.register::<Palette>();
        world.register::<Position>();
        world.register::<Velocity>();
        world
    }

    fn build_dispatcher() -> Dispatcher<'a, 'a> {
        DispatcherBuilder::new()
            .with(Movement, "movement", &[])
            .build()
    }

    pub fn new(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        background_name: &str,
    ) -> Result<Self, SceneError> {
        let map_data = store
            .get::<MapData>(&warmy::SimpleKey::from("/map.yaml"), ctx)?
            .borrow()
            .clone();
        let piv_res = store.get::<PivImage>(&SimpleKey::from(map_data.background.clone()), ctx)?;
        let mut background: Vec<graphics::Image> = Vec::new();
        let mut piv = piv_res.borrow_mut();
        background.push(graphics::Image::from_rgba8(
            ctx,
            512,
            512,
            &piv.to_rgba8_512(),
        )?);

        piv.palette[21..24].rotate_right(1);
        background.push(graphics::Image::from_rgba8(
            ctx,
            512,
            512,
            &piv.to_rgba8_512(),
        )?);

        piv.palette[21..24].rotate_right(1);
        background.push(graphics::Image::from_rgba8(
            ctx,
            512,
            512,
            &piv.to_rgba8_512(),
        )?);

        piv.palette[21..24].rotate_right(1);

        // world
        //     .create_entity()

        //     .with(Position { 10, 10 })

        Ok(Self {
            specs_world: Self::build_world(),
            dispatcher: Self::build_dispatcher(),
            map_data,
            background,
            background_frame: 0,
            current_background_image: 0,
        })
    }

    fn draw_background_map(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        let draw_params = graphics::DrawParam::default().scale(game.screen_scale);
        graphics::draw(
            ctx,
            &self.background[self.current_background_image],
            draw_params,
        )?;
        Ok(())
    }
}

impl<'a> Scene<Game, InputEvent> for MapScene<'a> {
    fn update(&mut self, game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        self.specs_world.maintain();
        self.background_frame += 1;
        if self.background_frame == MAP_ANIMATION_SPEED {
            self.current_background_image += 1;
            self.current_background_image %= self.background.len();
        }
        self.background_frame %= MAP_ANIMATION_SPEED;
        SceneSwitch::None
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        self.draw_background_map(game, ctx);

        let palette_storage = self.specs_world.read_storage::<Palette>();

        let position_storage = self.specs_world.read_storage::<Position>();
        let draw_storage = self.specs_world.read_storage::<Draw>();
        let entities = self.specs_world.entities();
        for (position, draw, entity) in (&position_storage, &draw_storage, &entities).join() {
            println!("test");
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "Map"
    }

    fn input(&mut self, gameworld: &mut Game, event: InputEvent, started: bool) {
        // let entities = self.specs_world.entities();
        // let mut controllers = self.specs_world.write_storage::<Controller>();
    }
}
