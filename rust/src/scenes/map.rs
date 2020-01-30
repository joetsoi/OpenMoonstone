use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

// use failure::{err_msg, Error};
use ggez::nalgebra::{Point2, Vector2};
use ggez::{graphics, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use serde_derive::{Deserialize, Serialize};
use specs::world::{Builder, Index};
use specs::{Dispatcher, DispatcherBuilder, Join, World, WorldExt};
use warmy::{SimpleKey, Store, StoreErrorOr};

use loadable_yaml_macro_derive::LoadableYaml;

use crate::animation::Image as SpriteImage;
use crate::animation::Sprite;
// TODO: move these components to common module out of combat
use crate::campaign::components::MapIntent;
use crate::campaign::systems::map_boundary::Boundary;
use crate::campaign::systems::{MapCommander, RestrictMovementToMapBoundary, SetMapVelocity};
use crate::combat::components::{Controller, Draw, Facing, Palette, Position, Velocity};
use crate::combat::systems::Movement;
use crate::error::LoadError;
use crate::game::{Game, SceneState};
use crate::input;
use crate::input::{Axis, Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::piv::{palette_swap, Colour, PivImage};
use crate::scenes::world::draw_entities;
use crate::scenes::FSceneSwitch;
use crate::text::Image;

const MAP_ANIMATION_SPEED: u32 = 6;

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

    pub palette: Vec<Colour>,
}

impl<'a> MapScene<'a> {
    fn build_world() -> World {
        let mut world = World::new();
        world.register::<Draw>();
        world.register::<Palette>();
        world.register::<Position>();
        world.register::<Velocity>();
        world.register::<Controller>();
        world.register::<MapIntent>();
        world
    }

    fn build_dispatcher() -> Dispatcher<'a, 'a> {
        DispatcherBuilder::new()
            .with(MapCommander, "map_commander", &[])
            .with(SetMapVelocity, "velocity", &["map_commander"])
            .with(
                RestrictMovementToMapBoundary,
                "restrict_movement",
                &["velocity"],
            )
            .with(Movement, "movement", &["restrict_movement"])
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

        let mut specs_world = Self::build_world();
        specs_world.insert(Boundary {
            x: 0,
            y: 0,
            w: 310,
            h: 190,
        });

        let sprite_res = store
            .get::<Sprite>(&SimpleKey::from(format!("/{}.yaml", "mi")), ctx)
            // TODO fix error handling, make this ?
            .expect("error getting sprite in build entity");
        let sprite = sprite_res.borrow();
        specs_world
            .create_entity()
            .with(Position { x: 10, y: 10 })
            .with(Velocity {
                ..Default::default()
            })
            .with(Draw {
                frame: sprite.animations["blue_knight"].frames[0].clone(),
                animation: "blue_knight".to_string(),
                resource_name: "mi".to_string(),
                direction: Facing::default(),
            })
            .with(Controller {
                x_axis: Axis::Horz1,
                y_axis: Axis::Vert1,
                button: Button::Fire1,
                ..Default::default()
            })
            .with(MapIntent {
                ..Default::default()
            })
            .build();

        Ok(Self {
            specs_world: specs_world,
            dispatcher: Self::build_dispatcher(),
            map_data,
            background,
            background_frame: 0,
            current_background_image: 0,
            palette: piv.palette.to_vec(),
        })
    }

    fn draw_background_map(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        // let draw_params = graphics::DrawParam::default().scale(game.screen_scale);
        graphics::draw(
            ctx,
            &self.background[self.current_background_image],
            // draw_params,
            graphics::DrawParam::default(),
        )?;
        Ok(())
    }

    fn update_controllers(&mut self, input: &input::InputState) {
        let entities = self.specs_world.entities();
        let mut controllers = self.specs_world.write_storage::<Controller>();
        for (e, controller) in (&*entities, &mut controllers).join() {
            controller.x = input.get_axis_raw(controller.x_axis) as i32;
            controller.y = input.get_axis_raw(controller.y_axis) as i32;
            controller.fire = input.get_button_down(controller.button);
        }
    }
}

impl<'a> Scene<Game, InputEvent> for MapScene<'a> {
    fn update(&mut self, game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        self.update_controllers(&game.input);
        self.dispatcher.dispatch_par(&self.specs_world);
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
        // since some of the campaign map is transparent, a sprite passing over
        // the transparent area would "colour in" that area, leaving behind the
        // ghost image of the sprite on those pixels, we clear the screen each
        // frame to get rid of these artifacts.
        graphics::clear(ctx, graphics::Color::new(0.0, 0.0, 0.0, 1.0));
        self.draw_background_map(game, ctx);
        draw_entities(&self.specs_world, &self.palette, None, game, ctx);
        Ok(())
    }

    fn name(&self) -> &str {
        "Map"
    }

    fn input(&mut self, gameworld: &mut Game, event: InputEvent, started: bool) {
        // let entities = self.specs_world.entities();
        // let mut controllers = self.specs_world.write_storage::<Controller>();
        // for (e, controller) in (&*entities, &mut controllers).join() {
        //     let x = gameworld.input.get_axis_raw(controller.x_axis);
        //     controller.x = gameworld.input.get_axis_raw(controller.x_axis) as i32;
        //     controller.y = gameworld.input.get_axis_raw(controller.y_axis) as i32;
        //     controller.fire = gameworld.input.get_button_down(controller.button);
        //     // println!("input {:?}", controller);
        // }
    }
}
