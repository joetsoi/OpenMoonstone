use std::collections::hash_map::Entry::{Occupied, Vacant};

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::iter;

// use failure::{err_msg, Error};
use ggez::nalgebra::{Point2, Vector2};
use ggez::{graphics, timer, Context, GameResult};
use ggez_goodies::scene::{Scene, SceneSwitch};
use serde_derive::{Deserialize, Serialize};
use specs::world::{Builder, Index};
use specs::{Dispatcher, DispatcherBuilder, EntityBuilder, Join, Read, World, WorldExt, Write};
use warmy::load::Load;
use warmy::{Res, SimpleKey, Store, StoreErrorOr};
// use warmy::ron::Ron;

use loadable_yaml_macro_derive::LoadableYaml;

use super::transition::FadeStyle;
use super::Fade;
use super::NextDay;

use crate::animation::Image as SpriteImage;
use crate::animation::{Frame, Sprite, SpriteData};
// TODO: move these components to common module out of combat
use crate::campaign::components::{Endurance, HitBox, MapIntent, OnHoverImage, TimeSpentOnTerrain};
use crate::campaign::movement_cost::CampaignMap;
use crate::campaign::systems::map_boundary::Boundary;
use crate::campaign::systems::{
    EnduranceTracker, HighlightOnHover, HighlightPlayer, MapCommander, NextPlayer, PrepareNextDay,
    RestrictMovementToMapBoundary, SetMapVelocity, TerrainCost,
};
use crate::combat::components::{Controller, Draw, Facing, Palette, Position, Velocity};
use crate::combat::systems::Movement;
use crate::components::RenderOrder;
use crate::error::{LoadError, MoonstoneError};
use crate::game::{Game, SceneState};
use crate::input;
use crate::input::{Axis, Button, InputEvent};
use crate::objects::TextureAtlas;
use crate::piv::{extract_palette, palette_swap, Colour, ColourOscillate, PivImage};
// use crate::ron::GameRon;
use crate::ron::{FromRon, GameRon};
use crate::scenes::world::draw_entities;
use crate::scenes::FSceneSwitch;
use crate::text::Image;

const MAP_ANIMATION_SPEED: u32 = 12;

pub struct FlashingPalettes {
    pub palettes: Vec<Vec<Colour>>,
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

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum LocationKind {
    Lair,
    Village,
    City,
    Stonehenge,
    Valley,
    WizardTower,
}

impl Default for LocationKind {
    fn default() -> Self {
        LocationKind::Lair
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub kind: LocationKind,
    pub image: Option<SpriteImage>,
    pub hover_image: Option<SpriteImage>,
    pub x: i32,
    pub y: i32,
    pub player: Option<u32>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Locations {
    pub locations: Vec<Location>,
}

struct MapState<'a> {
    players: Vec<Index>,
    current_player: &'a Index,
    day: u32,
}

#[derive(Debug, Default, Clone)]
pub struct OrderedEntities {
    entities: Vec<Index>,
    curr: usize,
    pub player_done: bool,
}

impl Iterator for OrderedEntities {
    type Item = Index;

    fn next(&mut self) -> Option<Self::Item> {
        self.curr += 1;
        self.entities.get(self.curr).and_then(|x| Some(*x))
    }
}

impl OrderedEntities {
    pub fn current(&self) -> Option<&Index> {
        self.entities.get(self.curr)
    }

    pub fn reset(&mut self) {
        self.curr = 0;
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct TurnOver(pub bool);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileList(pub HashMap<String, String>);

pub struct MapScene<'a> {
    pub specs_world: World,
    pub dispatcher: Dispatcher<'a, 'a>,

    // map_data: MapData,
    pub background: Vec<graphics::Image>,
    background_frame: u32,
    current_background_image: usize,

    pub palette: Vec<Colour>,
    day: u32,
}

impl<'a> MapScene<'a> {
    fn build_world() -> World {
        let mut world = World::new();
        world.register::<Draw>();
        world.register::<Endurance>();
        world.register::<HitBox>();
        world.register::<OnHoverImage>();
        world.register::<Palette>();
        world.register::<Position>();
        world.register::<RenderOrder>();
        world.register::<Velocity>();
        world.register::<Controller>();
        world.register::<MapIntent>();
        world.register::<TimeSpentOnTerrain>();
        world
    }

    fn build_dispatcher() -> Dispatcher<'a, 'a> {
        DispatcherBuilder::new()
            .with(MapCommander, "map_commander", &[])
            .with(TerrainCost, "terrain_cost", &["map_commander"])
            .with(SetMapVelocity, "velocity", &["terrain_cost"])
            .with(
                RestrictMovementToMapBoundary,
                "restrict_movement",
                &["velocity"],
            )
            .with(Movement, "movement", &["restrict_movement"])
            .with(NextPlayer, "next_player", &[])
            .with(PrepareNextDay, "prepare_next_day", &["next_player"])
            .with(
                EnduranceTracker,
                "endurance_tracker",
                &["movement", "prepare_next_day"],
            )
            .with(HighlightOnHover, "highlight_on_hover", &["movement"])
            .with(HighlightPlayer, "highlight_player", &[])
            .build()
    }

    fn setup_background_map(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        background_name: &str,
    ) -> Result<Vec<graphics::Image>, MoonstoneError> {
        let piv_res = store.get::<PivImage>(&SimpleKey::from(background_name), ctx)?;
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
        Ok(background)
    }

    fn build_knight_entity(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        world: &'a mut World,
        background_name: &str,
    ) -> Result<Index, MoonstoneError> {
        let piv_res = store
            .get::<PivImage>(&SimpleKey::from(background_name), ctx)
            .unwrap();
        let piv = piv_res.borrow();

        let atlas = store.get::<TextureAtlas>(&SimpleKey::from("mi.c"), ctx)?;
        // the first image in mi.c is the blue knight head.
        let knight_rect = atlas.borrow().rects[0];
        let knight_width = atlas.borrow().visible_widths[0];

        let sprite_res = store.get::<Sprite>(&SimpleKey::from(format!("/{}.yaml", "mi")), ctx)?;
        let sprite = sprite_res.borrow();
        let entity = world
            .create_entity()
            .with(Position { x: 10, y: 10 })
            .with(Velocity {
                ..Default::default()
            })
            .with(Draw {
                frame: sprite.animations["selected"].frames[0].clone(),
                animation: "selected".to_string(),
                resource_name: "blue_knight".to_string(),
                direction: Facing::default(),
            })
            .with(Endurance { max: 96, used: 0 })
            .with(Palette {
                name: "0".to_string(),
                palette: piv.palette.clone(),
            })
            .with(HitBox {
                w: knight_width,
                h: knight_rect.h,
            })
            .with(Controller {
                x_axis: Axis::Horz1,
                y_axis: Axis::Vert1,
                button: Button::Fire1,
                ..Default::default()
            })
            .with(RenderOrder { depth: 1 })
            .with(MapIntent {
                ..Default::default()
            })
            .with(TimeSpentOnTerrain {
                ..Default::default()
            })
            .build();
        Ok(entity.id())
    }

    fn build_locations(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        world: &'a mut World,
        background_name: &str,
    ) -> Result<(), MoonstoneError> {
        let locations_res = store.get_by::<GameRon<Locations>, FromRon>(
            &SimpleKey::from("/locations.ron"),
            ctx,
            FromRon,
        )?;
        let piv_res = store
            .get::<PivImage>(&SimpleKey::from(background_name), ctx)
            .unwrap();
        let piv = piv_res.borrow();

        let atlas = store.get::<TextureAtlas>(&SimpleKey::from("mi.c"), ctx)?;
        for l in locations_res.borrow().0.locations.iter() {
            let sprite_res =
                store.get::<Sprite>(&SimpleKey::from(format!("/{}.yaml", "mi")), ctx)?;
            let sprite = sprite_res.borrow();

            let mut entity_builder = world
                .create_entity()
                .with(Position { x: l.x, y: l.y })
                .with(Palette {
                    name: "0".to_string(),
                    palette: piv.palette.clone(),
                })
                .with(RenderOrder { depth: 0 })
                .with(OnHoverImage {
                    image: l.image.clone(),
                    hover: l.hover_image.clone(),
                })
                .with(Draw {
                    frame: Frame { images: vec![] },
                    animation: "".to_string(),
                    resource_name: "mi".to_string(),
                    direction: Facing::default(),
                });

            if let Some(i) = l.image.as_ref().or(l.hover_image.as_ref()) {
                let rect = atlas.borrow().rects[i.image];
                let width = atlas.borrow().visible_widths[i.image];
                entity_builder = entity_builder.with(HitBox {
                    w: width,
                    h: rect.h,
                })
            }

            entity_builder.build();
        }
        Ok(())
    }

    fn insert_palettes(specs_world: &mut World, piv: &PivImage) -> Result<(), MoonstoneError> {
        let mut swap_colour = extract_palette(&[0xff]).first().unwrap().clone();
        swap_colour.a = 255;
        let mut oscillate = ColourOscillate::new(piv.palette[31], swap_colour);
        let mut colours = (0..30)
            .map(|_| oscillate.next().unwrap())
            .collect::<Vec<_>>();
        colours.insert(0, piv.palette[31].clone());

        let mut palettes = Vec::new();
        for c in &colours {
            let mut p = piv.palette.clone();
            p[31] = c.clone();
            palettes.push(p);
        }
        specs_world.insert(FlashingPalettes { palettes });
        Ok(())
    }

    fn insert_campaign_map(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        specs_world: &mut World,
    ) -> Result<(), MoonstoneError> {
        let campaign_map_res = store.get_by::<GameRon<CampaignMap>, FromRon>(
            &SimpleKey::from("/campaign_map.ron"),
            ctx,
            FromRon,
        )?;
        specs_world.insert(campaign_map_res.borrow().0.clone());
        Ok(())
    }

    fn insert_boundary(specs_world: &mut World) -> Result<(), MoonstoneError> {
        specs_world.insert(Boundary {
            x: 0,
            y: 0,
            w: 310,
            h: 190,
        });
        Ok(())
    }

    fn insert_sprite_data(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        specs_world: &mut World,
    ) -> Result<(), MoonstoneError> {
        let entities = store.get_by::<GameRon<FileList>, FromRon>(
            &SimpleKey::from("/map_entities.ron"),
            ctx,
            FromRon,
        )?;

        let mut sprites: HashMap<String, Sprite> = HashMap::new();
        for (name, file_name) in &((entities.borrow().0).0) {
            let sprite = store.get_by::<GameRon<Sprite>, FromRon>(
                &SimpleKey::from(file_name.clone()),
                ctx,
                FromRon,
            )?;
            sprites.insert(name.clone(), sprite.borrow().0.clone());
        }
        specs_world.insert(SpriteData { sprites });
        Ok(())
    }

    pub fn new(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        background_name: &str,
        num_players: u32,
    ) -> Result<Self, MoonstoneError> {
        let background = MapScene::setup_background_map(ctx, store, &background_name)?;

        let mut specs_world = Self::build_world();

        let player_index =
            MapScene::build_knight_entity(ctx, store, &mut specs_world, &background_name)?;
        let players = OrderedEntities {
            entities: vec![player_index],
            curr: 0,
            player_done: false,
        };
        specs_world.insert(players);
        specs_world.insert(TurnOver(false));

        MapScene::insert_boundary(&mut specs_world)?;
        MapScene::insert_campaign_map(ctx, store, &mut specs_world)?;

        let piv_res = store.get::<PivImage>(&SimpleKey::from(background_name), ctx)?;
        let piv = piv_res.borrow();
        MapScene::insert_palettes(&mut specs_world, &*piv)?;
        MapScene::build_locations(ctx, store, &mut specs_world, background_name)?;

        MapScene::insert_sprite_data(ctx, store, &mut specs_world)?;

        // let map_data = store
        //     .get::<MapData>(&warmy::SimpleKey::from("/map.yaml"), ctx)?
        //     .borrow()
        //     .clone();
        Ok(Self {
            specs_world: specs_world,
            dispatcher: Self::build_dispatcher(),
            // map_data,
            background,
            background_frame: 0,
            current_background_image: 0,
            palette: piv.palette.to_vec(),
            day: 0,
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
    fn update(&mut self, game: &mut Game, ctx: &mut Context) -> FSceneSwitch {
        self.update_controllers(&game.input);
        self.dispatcher.dispatch_par(&self.specs_world);
        self.specs_world.maintain();
        self.background_frame += 1;
        if self.background_frame == MAP_ANIMATION_SPEED {
            self.current_background_image += 1;
            self.current_background_image %= self.background.len();
        }
        self.background_frame %= MAP_ANIMATION_SPEED;
        let mut turn_over: Write<TurnOver> = self.specs_world.system_data();
        match turn_over.0 {
            true => {
                turn_over.0 = false;
                SceneSwitch::PushMultiple(vec![
                    // Once we finish the next day scene, want to fade back into
                    // the map, hence the extra fade here.
                    Box::new(Fade::new(274, 1, FadeStyle::In)),
                    Box::new(
                        NextDay::new(ctx, &mut game.store).expect("failed to init next day scene"),
                    ),
                    Box::new(Fade::new(274, 1, FadeStyle::In)),
                ])
            }
            false => SceneSwitch::None,
        }
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
