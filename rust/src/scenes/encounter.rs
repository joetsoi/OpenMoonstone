use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{HashMap, HashSet};
use std::fmt;

use ggez::conf::NumSamples;
use ggez::nalgebra::Point2;
use ggez::{filesystem, graphics, Context, GameResult};
use ggez_goodies::scene;
use ron::de::from_reader;
use serde_derive::Deserialize;
use specs::world::{Builder, Index};
use specs::{Dispatcher, DispatcherBuilder, Entity, EntityBuilder, Join, World, WorldExt};
use warmy::{SimpleKey, Store};

use super::transition::FadeStyle;
use super::Fade;
use crate::animation::{Sprite, SpriteData};
use crate::combat::components::{
    AiState,
    AnimationState,
    Body,
    Collided,
    Controller,
    DaggersInventory,
    Draw,
    Facing,
    Health,
    Intent,
    MustLive,
    Palette,
    Position,
    SpawnPool,
    State,
    UnitType,
    Velocity,
    WalkingState,
    Weapon,
};
use crate::combat::damage::DamageTables;
use crate::combat::systems::boundary::Boundary;
use crate::combat::systems::health::CombatDone;
use crate::combat::systems::{
    ActionSystem,
    AiDirection,
    Animation,
    BlackKnightAi,
    CheckCollisions,
    CheckEndOfCombat,
    Commander,
    ConfirmVelocity,
    DestroySpawnPool,
    EntityDeath,
    EntityEntityCollision,
    Movement,
    OutOfBounds,
    PlayerDirection,
    ResolveCollisions,
    RestrictMovementToBoundary,
    SpawnControl,
    StateUpdater,
    UpdateBoundingBoxes,
    UpdateImage,
    VelocitySystem,
};
use crate::components::RenderOrder;
use crate::error::MoonstoneError;
use crate::files::collide::CollisionBoxes;
use crate::files::terrain::{Background, SCENERY_RECTS};
use crate::files::TerrainFile;
use crate::game::{Game, SceneState};
use crate::input;
use crate::objects::TextureAtlas;
use crate::palette::PaletteSwaps;
use crate::piv::{palette_swap, Colour, PivImage};
use crate::rect::Rect;
use crate::ron::{FromDosFilesRon, FromRon, GameRon};
use crate::scenes::world::draw_entities;
use crate::scenes::FSceneSwitch;
use crate::systems::SortRenderByYPosition;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Deserialize)]
pub enum Asset {
    BlueKnight,
    OrangeKnight,
    RedKnight,
    GreenKnight,
    BlackKnight,
    BlueFlashKnight,
    OrangeFlashKnight,
    RedFlashKnight,
    GreenFlashKnight,
    BlackFlashKnight,
    TroggSpear,
    Grassland,
    Forest,
    Swampland,
    Wasteland,
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

impl From<Background> for Asset {
    fn from(background: Background) -> Self {
        match background {
            Background::Grassland => Asset::Grassland,
            Background::Forest => Asset::Forest,
            Background::Swampland => Asset::Swampland,
            Background::Wasteland => Asset::Wasteland,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct EncounterTextures {
    pub data: HashMap<String, TextureAtlas>,
}

const TICKS_TO_WAIT: u32 = 35;

// The original encounter scenes ran at half the FPS of the other scenes, this
// is presumably because that meant that half the number of frames of art was
// needed for a sprite saving on precious disk space.
const TICKS_PER_UPDATE: u32 = 2;

pub struct EncounterScene<'a> {
    // pub drawable_world: DrawableWorld,
    pub specs_world: World,
    pub dispatcher: Dispatcher<'a, 'a>,
    pub background: graphics::Canvas,
    pub palette: Vec<Colour>,
    player_1: Index,
    player_2: Option<Index>,
    player_3: Option<Index>,
    player_4: Option<Index>,

    //
    current_update_tick: u32,
    // the number of ticks since the encounter is done
    ticks_after: u32,
    // we do the fade out first, pop back to this scene then pop the encounter.
    fade_out_done: bool,
}

impl<'a> EncounterScene<'a> {
    fn build_world() -> World {
        let mut world = World::new();
        world.register::<AiState>();
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
        world.register::<RenderOrder>();
        world.register::<State>();
        world.register::<SpawnPool>();
        world.register::<UnitType>();
        world.register::<Velocity>();
        world.register::<WalkingState>();
        world.register::<Weapon>();
        world
    }

    fn build_dispatcher() -> Dispatcher<'a, 'a> {
        DispatcherBuilder::new()
            .with(Commander, "commander", &[])
            .with(PlayerDirection, "player_direction", &["commander"])
            .with(BlackKnightAi, "black_knight_ai", &[])
            .with(AiDirection, "ai_direction", &["black_knight_ai"])
            .with(
                ActionSystem,
                "action",
                &["player_direction", "ai_direction"],
            )
            .with(EntityDeath, "entity_death", &["action"])
            .with(DestroySpawnPool, "destroy_spawn_pool", &["entity_death"])
            .with(
                CheckEndOfCombat,
                "check_end_of_combat",
                &["destroy_spawn_pool"],
            )
            .with(
                SpawnControl,
                "spawn_control",
                &["entity_death", "destroy_spawn_pool"],
            )
            .with(
                VelocitySystem,
                "velocity",
                &["player_direction", "ai_direction"],
            )
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
            .with(
                SortRenderByYPosition,
                "sort_render_by_y_position",
                &["resolve_collisions"],
            )
            .with(OutOfBounds, "out_of_bounds", &[])
            // .with_thread_local(Renderer {
            //     store: Store::new(StoreOpt::default()).expect("store creation"),
            // })
            .build()
    }

    fn load_resources(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        world: &mut World,
    ) -> Result<(), MoonstoneError> {
        let damage_tables = store
            .get::<DamageTables>(&SimpleKey::from("/damage.yaml"), ctx)
            .expect("error loading damage.yaml");
        world.insert(damage_tables.borrow().clone());
        world.insert(CombatDone(false));
        Ok(())
    }

    fn load_sprite_data(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        world: &mut World,
        entity_names: &[&str],
    ) -> Result<(), MoonstoneError> {
        let entities_res = store
            .get_by::<GameRon<HashMap<String, String>>, FromRon>(
                &SimpleKey::from("/entities.ron"),
                ctx,
                FromRon,
            )
            .expect("error loading entities.ron");
        let entities = &entities_res.borrow().0;
        println!("ent {:?}", entities);

        let mut sprites: HashMap<String, Sprite> = HashMap::new();
        let mut atlas_names: HashSet<String> = HashSet::new();
        for name in entity_names {
            let res_file = entities.get(*name).unwrap();
            // TODO: Fix to allow ? syntax
            let sprite_res = store
                .get_by::<Sprite, FromRon>(&warmy::SimpleKey::from(res_file.clone()), ctx, FromRon)
                .expect("error loading entity ron file");
            sprites.insert(name.to_string(), (*sprite_res.borrow()).clone());

            for i in sprite_res
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
        world.insert(SpriteData { sprites });
        let mut image_sizes: HashMap<String, Vec<Rect>> = HashMap::new();
        let mut texture_atlases: HashMap<String, TextureAtlas> = HashMap::new();
        for atlas_name in atlas_names {
            let atlas = store
                .get::<TextureAtlas>(&SimpleKey::from(atlas_name.clone()), ctx)
                // TODO: Fix to allow ? syntax
                .expect("Error loading texture atlas");
            image_sizes.insert(atlas_name.clone(), atlas.borrow().rects.clone());
            texture_atlases.insert(atlas_name.clone(), atlas.borrow().clone());
        }
        world.insert(EncounterTextures {
            data: texture_atlases,
        });
        Ok(())
    }

    // fn create_player_entity(entity_builder: EntityBuilder) -> Entity {
    //     entity_builder
    //         .with(Controller {
    //             ..Default::default()
    //         })
    //         .build()
    // }

    fn build_entity(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        world: &'a mut World,
        resource: &str,
        raw_palette: &[u16],
        palette_name: &str,
        x: i32,
        y: i32,
        direction: Facing,
    ) -> EntityBuilder<'a> {
        let sprite_res = store
            .get_by::<Sprite, FromRon>(&SimpleKey::from(format!("/{}.ron", resource)), ctx, FromRon)
            // TODO fix error handling, make this ?
            // .expect("error getting sprite in build entity");
            .unwrap();
        let sprite = sprite_res.borrow();

        let swaps_res = store
            .get::<PaletteSwaps>(&SimpleKey::from("/palettes.yaml"), ctx)
            // TODO fix error handling, make this ?
            .expect("error loading palette.yaml");
        let swaps = swaps_res.borrow();
        let mut spawn_pool = SpawnPool::new(resource, x, y, direction);
        spawn_pool
            .character
            .position(x, y)
            .state(direction)
            .draw(
                &sprite.animations["entrance"].frames[0],
                "entrance",
                direction,
            )
            .palette(
                palette_name,
                &palette_swap(
                    &raw_palette,
                    &swaps.0.get(&palette_name.to_string()).expect("no palette"),
                ),
            );
        spawn_pool.spawn(world).unwrap()
    }

    pub fn build_spawn_pool(
        ctx: &mut Context,
        store: &mut Store<Context, SimpleKey>,
        // world: &'a mut World,
        resource: &str,
        raw_palette: &[u16],
        palette_name: &str,
        x: i32,
        y: i32,
        direction: Facing,
    ) -> SpawnPool {
        let sprite_res = store
            .get_by::<Sprite, FromRon>(&SimpleKey::from(format!("/{}.ron", resource)), ctx, FromRon)
            // TODO fix error handling, make this ?
            // .expect("error getting sprite in build entity");
            .unwrap();
        let sprite = sprite_res.borrow();

        let swaps_res = store
            .get::<PaletteSwaps>(&SimpleKey::from("/palettes.yaml"), ctx)
            // TODO fix error handling, make this ?
            .expect("error loading palette.yaml");
        let swaps = swaps_res.borrow();

        let mut spawn_pool = SpawnPool::new(resource, x, y, direction);
        spawn_pool
            .character
            .position(x, y)
            .state(direction)
            .draw(
                &sprite.animations["entrance"].frames[0],
                "entrance",
                Facing::default(),
            )
            .palette(
                palette_name,
                &palette_swap(
                    &raw_palette,
                    &swaps.0.get(&palette_name.to_string()).expect("no palette"),
                ),
            );
        spawn_pool
    }

    pub fn new(
        ctx: &mut Context,
        game: &mut Game,
        entity_names: &[&str],
        background_name: &str,
        terrain_name: &str,
    ) -> Result<Self, MoonstoneError> {
        let mut world = EncounterScene::build_world();
        EncounterScene::load_sprite_data(ctx, &mut game.store, &mut world, entity_names)?;
        EncounterScene::load_resources(ctx, &mut game.store, &mut world)?;

        let piv = game
            .store
            .get::<PivImage>(&SimpleKey::from(background_name), ctx)
            // TODO fix error handling, make this ?
            .expect("Error loading piv background");

        let file = filesystem::open(ctx, "/palettes.ron")?;
        let swaps =
            from_reader::<filesystem::File, HashMap<Asset, HashMap<usize, u16>>>(file).unwrap();
        let mut piv_clone: PivImage = piv.borrow().clone();
        piv_clone = piv_clone
            // .swap_colours(swaps.get(&Asset::Grassland).unwrap())
            .build_palette();

        let scenery = game
            .store
            .get_by::<TerrainFile, FromDosFilesRon>(
                &SimpleKey::from(terrain_name.to_string()),
                ctx,
                FromDosFilesRon,
            )
            // TODO fix error handling, make this ?
            .expect("Error loading terrain file while building encounter scene");
        let scenery_piv = game
            .store
            .get::<PivImage>(
                &SimpleKey::from(scenery.borrow().background.to_atlas_name()),
                ctx,
            )
            // TODO fix error handling, make this ?
            .expect("Error loading piv background")
            .borrow()
            .clone()
            // .swap_colours(swaps.get(&Asset::Grassland).unwrap())
            .swap_colours(swaps.get(&Asset::TroggSpear).unwrap())
            .build_palette();

        let (background, y_max) = EncounterScene::build_background_canvas(
            ctx,
            game,
            &mut world,
            &piv_clone,
            &scenery.borrow(),
        )?;
        let collide_hit = game
            .store
            .get::<CollisionBoxes>(&SimpleKey::from("collide"), ctx)
            // TODO fix error handling, make this ?
            .expect("Error loading collision boxes");
        world.insert(collide_hit.borrow().clone());

        // piv.raw_with_swap();

        let (player_1, player_2, player_3, player_4) = EncounterScene::create_entities(
            ctx,
            game,
            &mut world,
            &scenery_piv.raw_palette,
            // &piv.borrow().raw_palette,
            y_max,
        );

        // let y = EncounterScene::next_starting_position(game, y_max as i32);
        // let player_1 = EncounterScene::build_entity(
        //     ctx,
        //     &mut game.store,
        //     &mut world,
        //     "knight",
        //     &piv.borrow().raw_palette,
        //     "blue_knight",
        //     250,
        //     y,
        //     Facing::Left,
        // )
        // .with(Controller {
        //     ..Default::default()
        // })
        // .build();

        // let y = EncounterScene::next_starting_position(game, y_max as i32);
        // let player_2 = EncounterScene::build_entity(
        //     ctx,
        //     &mut game.store,
        //     &mut world,
        //     "knight",
        //     &piv.borrow().raw_palette,
        //     "green_knight",
        //     30,
        //     y,
        //     Facing::default(),
        // )
        // // .with(Controller {
        // //     ..Default::default()
        // // })
        // .with(AiState {
        //     class: "black_knight".to_string(),
        //     target: Some(player_1),
        //     y_range: 4,
        //     close_range: 80,
        //     long_range: 100,
        // })
        // .build();

        let palette: Vec<Colour> = piv_clone.palette.to_vec();
        Ok(EncounterScene {
            // drawable_world,
            palette,
            specs_world: world,
            background,
            dispatcher: EncounterScene::build_dispatcher(),
            player_1,
            player_2,
            player_3,
            player_4,
            current_update_tick: 0,
            ticks_after: 0,
            fade_out_done: false,
        })
    }

    fn build_background_canvas(
        ctx: &mut Context,
        game: &mut Game,
        world: &mut World,
        background: &PivImage,
        scenery: &TerrainFile,
    ) -> Result<(graphics::Canvas, u32), MoonstoneError> {
        let background_image =
            graphics::Image::from_rgba8(ctx, 320, 200, &background.to_rgba8()).unwrap();
        // We create a canvas using the screen coordinates instead of the window height as
        // the current window height could have been resized, this causes some odd problems
        // where anything rendered to the canvas is a few pixels off
        let screen_coordinates = graphics::screen_coordinates(ctx);
        let background = graphics::Canvas::new(
            ctx,
            screen_coordinates.w as u16,
            screen_coordinates.h as u16,
            NumSamples::One,
        )?;
        // We reset the transformation matrix here to the default here and reapply the game scale
        // after. TODO: Investigate why we can't use a canvas of 320x200. If we've set the matrix
        // to the default then everything should be drawing to 320x200 instead of the current
        // screen coordinates that have been scaled up.
        graphics::set_transform(ctx, graphics::DrawParam::default().to_matrix());
        graphics::apply_transformations(ctx)?;
        let screen_origin = Point2::new(0.0, 0.0);

        graphics::set_canvas(ctx, Some(&background));
        graphics::draw(
            ctx,
            &background_image,
            graphics::DrawParam::default().dest(screen_origin),
        )?;

        let y_max = EncounterScene::draw_terrain(ctx, game, world, scenery)?;
        graphics::set_canvas(ctx, None);
        let scale_matrix = graphics::DrawParam::default()
            .scale(game.screen_scale)
            .to_matrix();
        graphics::push_transform(ctx, Some(scale_matrix));
        graphics::apply_transformations(ctx)?;
        Ok((background, y_max))
    }

    fn create_entities(
        ctx: &mut Context,
        game: &mut Game,
        world: &mut World,
        raw_palette: &[u16],
        y_max: u32,
    ) -> (Index, Option<Index>, Option<Index>, Option<Index>) {
        let mut control_map = HashMap::new();
        control_map.insert(
            0,
            (input::Axis::Horz1, input::Axis::Vert1, input::Button::Fire1),
        );
        control_map.insert(
            1,
            (input::Axis::Horz2, input::Axis::Vert2, input::Button::Fire2),
        );
        control_map.insert(
            2,
            (input::Axis::Horz3, input::Axis::Vert3, input::Button::Fire3),
        );
        control_map.insert(
            3,
            (input::Axis::Horz4, input::Axis::Vert4, input::Button::Fire4),
        );

        let starting_x = [250, 30, 240, 40];
        let colours = ["blue_knight", "green_knight", "red_knight", "orange_knight"];

        // let x = starting_x[0];
        // let y = EncounterScene::next_starting_position(game, y_max as i32);
        // let facing = match x {
        //     x if x < 160 => Facing::Right,
        //     _ => Facing::Left,
        // };
        // let player_1 = EncounterScene::build_entity(
        //     ctx,
        //     &mut game.store,
        //     world,
        //     "knight",
        //     raw_palette,
        //     colours[0],
        //     x,
        //     y,
        //     facing,
        // )
        // .with(Controller {
        //     x_axis: input::Axis::Horz1,
        //     y_axis: input::Axis::Vert1,
        //     button: input::Button::Fire1,
        //     ..Default::default()
        // })
        // .build();

        let mut players: Vec<Entity> = Vec::new();

        for n in 0..game.num_players {
            let x = starting_x[n as usize];
            let y = EncounterScene::next_starting_position(game, y_max as i32);
            let facing = match x {
                x if x < 160 => Facing::Right,
                _ => Facing::Left,
            };
            let mapping = control_map.get(&n).unwrap();
            // EncounterScene::build_spawn_pool(
            //     ctx,
            //     &mut game.store,
            //     &mut world,
            //     "knight",
            //     &scenery_piv.raw_palette,
            //     "blue_knight",
            // );
            let mut spawn_pool = EncounterScene::build_spawn_pool(
                ctx,
                &mut game.store,
                // world,
                "knight",
                raw_palette,
                colours[n as usize],
                x,
                y,
                facing,
            );
            spawn_pool
                .character
                .controller(mapping.0, mapping.1, mapping.2);
            let player = world
                .create_entity()
                .with(spawn_pool)
                .with(MustLive {})
                .build();
            // let player = EncounterScene::build_entity(
            //     ctx,
            //     &mut game.store,
            //     world,
            //     "knight",
            //     raw_palette,
            //     colours[n as usize],
            //     x,
            //     y,
            //     facing,
            // )
            // .with(Controller {
            //     x_axis: mapping.0,
            //     y_axis: mapping.1,
            //     button: mapping.2,
            //     ..Default::default()
            // })
            // .build();
            players.push(player);
        }

        let player_1 = players.get(0).unwrap();
        if game.num_players == 1 {
            let y = EncounterScene::next_starting_position(game, y_max as i32);
            EncounterScene::build_entity(
                ctx,
                &mut game.store,
                world,
                "knight",
                raw_palette,
                "black_knight",
                30,
                y,
                Facing::default(),
            )
            .with(AiState {
                class: "black_knight".to_string(),
                target: Some(*player_1),
                y_range: 4,
                close_range: 80,
                long_range: 100,
            })
            .build();
        }

        (
            player_1.id(),
            players.get(1).and_then(|p| Some(p.id())),
            players.get(2).and_then(|p| Some(p.id())),
            players.get(3).and_then(|p| Some(p.id())),
        )
    }

    fn draw_terrain(
        ctx: &mut Context,
        game: &mut Game,
        world: &mut World,
        scenery: &TerrainFile,
    ) -> Result<u32, MoonstoneError> {
        // let terrain = game
        //     .store
        //     .get_by::<TerrainFile, FromDosFilesRon>(
        //         &SimpleKey::from(terrain_name.to_string()),
        //         ctx,
        //         FromDosFilesRon,
        //     )
        //     // TODO fix error handling, make this ?
        //     .expect("Error loading terrain file whlie drawing");

        // let file = filesystem::open(ctx, "/palettes.ron")?;
        // let swaps =
        //     from_reader::<filesystem::File, HashMap<Asset, HashMap<usize, u16>>>(file).unwrap();

        for p in &scenery.positions {
            let cmp = game
                .store
                .get::<PivImage>(&SimpleKey::from(p.atlas.clone()), ctx)
                // TODO fix error handling, make this ?
                .expect("error loading piv image in draw_terrain");

            let mut cmp_clone: PivImage = cmp.borrow().clone();
            cmp_clone = cmp_clone
                // .swap_colours(swaps.get(&Asset::Grassland).unwrap())
                .build_palette();
            let entry = format!("{}-{}", p.atlas, scenery.background);

            let ggez_image = match game.images.entry(entry) {
                Occupied(i) => i.into_mut(),
                Vacant(i) => i.insert(graphics::Image::from_rgba8(
                    ctx,
                    512u16,
                    512u16,
                    &cmp_clone.to_rgba8_512(),
                )?),
            };

            let rect = SCENERY_RECTS[p.image_number];

            let draw_params = graphics::DrawParam::default()
                .src(graphics::Rect {
                    x: rect.x as f32 / 512.0,
                    y: rect.y as f32 / 512.0,
                    w: rect.w as f32 / 512.0,
                    h: rect.h as f32 / 512.0,
                })
                .dest(Point2::new(p.x as f32, p.y as f32));
            graphics::draw(ctx, ggez_image, draw_params)?;
        }

        let y_max: u32 = scenery
            .headers
            .iter()
            .map(|h| h.y)
            .max()
            .expect("error getting ymax");
        world.insert(Boundary {
            y: y_max as i32 - 30,
            ..Default::default()
        });
        Ok(y_max)
    }

    fn update_controllers(&mut self, input: &input::InputState) {
        let entities = self.specs_world.entities();
        let mut controllers = self.specs_world.write_storage::<Controller>();
        for (_e, controller) in (&*entities, &mut controllers).join() {
            controller.x = input.get_axis_raw(controller.x_axis) as i32;
            controller.y = input.get_axis_raw(controller.y_axis) as i32;
            controller.fire = input.get_button_down(controller.button);
        }
    }

    fn next_starting_position(game: &mut Game, t: i32) -> i32 {
        game.encounter_starting_position = game.encounter_starting_position % 3 + 1;
        let s = 200 - t; // screen height - smallest t
        match game.encounter_starting_position {
            3 => s / 2 + t - 47,
            2 => s / 4 + t - 47,
            1 => s / 2 + s / 4 + t - 47,
            _ => panic!("set starting position failed"),
        }
    }
}

impl<'a> scene::Scene<Game, input::InputEvent> for EncounterScene<'a> {
    fn update(&mut self, game: &mut Game, _ctx: &mut Context) -> FSceneSwitch {
        self.current_update_tick = (self.current_update_tick + 1) % TICKS_PER_UPDATE;
        if self.current_update_tick == 0 {
            return scene::SceneSwitch::None;
        }
        self.specs_world.maintain();
        self.update_controllers(&game.input);
        self.dispatcher.dispatch_par(&self.specs_world);
        if self.specs_world.read_resource::<CombatDone>().0 {
            self.ticks_after += 1;
            if self.ticks_after > TICKS_TO_WAIT {
                if self.fade_out_done {
                    return scene::SceneSwitch::Pop; //shouldn't happen
                } else {
                    game.next_scene = SceneState::Menu;
                    game.practice_encounter = game.practice_encounter % 8 + 1;
                    return scene::SceneSwitch::push(Fade::new(274, 1, FadeStyle::Out));
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

        // draw background
        let lair = &self.background;
        graphics::draw(ctx, lair, graphics::DrawParam::default())?;

        draw_entities(
            &self.specs_world,
            &self.palette,
            Some(&self.background),
            game,
            ctx,
        )?;

        let body_storage = self.specs_world.read_storage::<Body>();

        // graphics::set_color(ctx, graphics::Color::new(0.4, 1.0, 0.0, 1.0))?;
        for body in (&body_storage).join() {
            if let Some(boxes) = &body.collision_boxes {
                for collision_box in boxes {
                    let mesh = graphics::MeshBuilder::new()
                        .rectangle(
                            graphics::DrawMode::stroke(1.0),
                            graphics::Rect {
                                x: (collision_box.rect.x) as f32,
                                y: (collision_box.rect.y) as f32,
                                w: collision_box.rect.w as f32,
                                h: collision_box.rect.h as f32,
                            },
                            graphics::Color::new(0.4, 1.0, 0.0, 1.0),
                        )
                        .build(ctx)?;
                    graphics::draw(ctx, &mesh, graphics::DrawParam::default())?;
                }
            }
        }

        let weapon_storage = self.specs_world.read_storage::<Weapon>();

        for weapon in (&weapon_storage).join() {
            if let Some(collision_rects) = &weapon.collision_points {
                for rect in collision_rects {
                    let mesh = graphics::MeshBuilder::new()
                        .rectangle(
                            graphics::DrawMode::stroke(1.0),
                            graphics::Rect {
                                x: rect.bounding.x as f32,
                                y: rect.bounding.y as f32,
                                w: rect.bounding.w as f32,
                                h: rect.bounding.h as f32,
                            },
                            graphics::Color::new(1.0, 0.0, 1.0, 1.0),
                        )
                        .build(ctx)?;
                    graphics::draw(ctx, &mesh, graphics::DrawParam::default())?;
                    for point in &rect.points {
                        let mesh = graphics::MeshBuilder::new()
                            .rectangle(
                                graphics::DrawMode::stroke(1.0),
                                graphics::Rect {
                                    x: point.x as i32 as f32,
                                    y: point.y as i32 as f32,
                                    w: 1.0,
                                    h: 1.0,
                                },
                                graphics::Color::new(1.0, 0.0, 1.0, 1.0),
                            )
                            .build(ctx)?;
                        graphics::draw(ctx, &mesh, graphics::DrawParam::default())?;
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
