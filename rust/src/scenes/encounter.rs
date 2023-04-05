use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    collections::HashMap,
    path,
};

use color_eyre::eyre::{eyre, Result, WrapErr};
use ggez::{
    filesystem,
    glam::Vec2,
    graphics::{self, Canvas, DrawParam, Image, ImageFormat, Rect, Sampler},
    Context,
};
use specs::world::{Builder, Index};
use specs::{Dispatcher, DispatcherBuilder, Entity, Join, World, WorldExt};

use crate::combat::resources::MoveDistances;
use crate::{
    animation::{Image as AnimationImage, Sprite, SpriteData},
    assets::Assets,
    combat::components::{
        AnimationState, Controller, DaggersInventory, Draw, Facing, Health, Intent, Position,
        State, UnitType, Velocity, WalkingState,
    },
    combat::systems::{
        ActionSystem, Animation, Commander, ConfirmVelocity, Movement, PlayerDirection,
        StateUpdater, UpdateImage, VelocitySystem,
    },
    files,
    files::terrain::{Background, SCENERY_RECTS},
    game, input, piv, scenes, scenestack,
};

pub struct EncounterBuilder {
    pub background: &'static str,
    pub terrain: &'static str,
}

impl EncounterBuilder {
    pub fn new(background: &'static str, terrain: &'static str) -> Self {
        Self {
            background,
            terrain,
        }
    }

    pub fn build<'a>(&self, ctx: &mut Context, assets: &mut Assets) -> Result<EncounterScene<'a>> {
        let background = self.build_background(ctx, assets)?;
        let mut world = World::new();
        world.register::<AnimationState>();
        world.register::<Controller>();
        world.register::<DaggersInventory>();
        world.register::<Draw>();
        world.register::<Position>();
        world.register::<Intent>();
        world.register::<State>();
        world.register::<UnitType>();
        world.register::<Velocity>();
        world.register::<WalkingState>();
        world.register::<Health>();
        let dispatcher = DispatcherBuilder::new()
            .with(Commander, "commander", &[])
            .with(PlayerDirection, "player_direction", &["commander"])
            .with(
                ActionSystem,
                "action",
                // &["player_direction", "ai_direction"],
                &["player_direction"],
            )
            .with(
                VelocitySystem,
                "velocity",
                // &["player_direction", "ai_direction"],
                &["player_direction"],
            )
            .with(
                ConfirmVelocity,
                "confirm_velocity",
                &[],
                // &["restrict_movement_to_boundary", "entity_collision"],
            )
            .with(Movement, "movement", &["confirm_velocity"])
            .with(Animation, "animation", &["movement"])
            .with(UpdateImage, "update_image", &["animation"])
            .with(StateUpdater, "state_updater", &["animation"])
            //, &["resolve_collisions"])
            .build();

        let sprite = Sprite::new(&files::read(ctx, "/knight.ron"));
        let move_distances: MoveDistances =
            ron::from_str(&files::read(ctx, "/movement.ron")).unwrap();
        let knight_move = move_distances.distances.get("knight").unwrap();

        let mut sprites: HashMap<String, Sprite> = HashMap::new();
        sprites.insert("knight".to_string(), sprite.clone());
        world.insert(SpriteData { sprites });

        world
            .create_entity()
            .with(UnitType {
                name: "knight".to_string(),
            })
            .with(Position { x: 50, y: 50 })
            .with(Velocity {
                ..Default::default()
            })
            .with(Draw {
                frame: sprite.animations.get("idle").unwrap().frames[0].clone(),
                animation: "idle".to_string(),
                direction: Facing::Left,
            })
            .with(AnimationState {
                ..Default::default()
            })
            .with(Intent {
                ..Default::default()
            })
            .with(State {
                ..Default::default()
            })
            .with(Controller {
                x_axis: input::Axis::Horz1,
                y_axis: input::Axis::Vert1,
                button: input::Button::Fire1,
                ..Default::default()
            })
            .with(WalkingState {
                step_distances: knight_move.clone(),
                ..Default::default()
            })
            .with(Health {
                ..Default::default()
            })
            .build();
        let piv = assets.piv.get(self.background).ok_or_else(|| {
            eyre!(format!(
                "{} has not been loaded as a piv asset",
                self.background
            ))
        })?;
        let palette = piv.palette.clone();

        Ok(EncounterScene {
            world,
            dispatcher,
            background,
            palette,
        })
    }

    fn build_background(&self, ctx: &mut Context, assets: &mut Assets) -> Result<Image> {
        let background = assets.piv.get(self.background).ok_or_else(|| {
            eyre!(format!(
                "{} has not been loaded as a piv asset",
                self.background
            ))
        })?;

        let background_image = Image::from_pixels(
            ctx,
            &background.to_rgba8(),
            graphics::ImageFormat::Rgba8UnormSrgb,
            320,
            200,
        );

        // Manually create frame in order to use render passes outside of draw
        // This allows us to draw the background once and reuse that image
        // in each frame
        //
        // https://github.com/ggez/ggez/issues/1056
        ctx.gfx.begin_frame()?;

        let canvas_image = Image::new_canvas_image(ctx, ImageFormat::Rgba8UnormSrgb, 320, 200, 1);
        let mut canvas = Canvas::from_image(ctx, canvas_image.clone(), Option::None);
        // Draw the basic background
        canvas.draw(&background_image, DrawParam::default());

        // Draw scenery from terrain tileset
        let scenery = assets.terrain.get(self.terrain).ok_or_else(|| {
            eyre!(format!(
                "{} has not been loaded as a terrain asset",
                self.terrain
            ))
        })?;

        for p in &scenery.positions {
            let cmp = assets.piv.get(&p.atlas).ok_or_else(|| {
                eyre!(format!(
                    "Failed to load terrain sprite sheet {} has not been loaded as a piv asset",
                    p.atlas
                ))
            })?;
            let entry = format!("{}-{}", p.atlas, scenery.background);

            let ggez_image = match assets.images.entry(entry) {
                Occupied(i) => i.into_mut(),
                Vacant(i) => i.insert(graphics::Image::from_pixels(
                    ctx,
                    &cmp.to_rgba8_512(),
                    graphics::ImageFormat::Rgba8UnormSrgb,
                    512u32,
                    512u32,
                )),
            };
            let rect = SCENERY_RECTS[p.image_number];
            let draw_params = graphics::DrawParam::default()
                .src(graphics::Rect {
                    x: rect.x as f32 / 512.0,
                    y: rect.y as f32 / 512.0,
                    w: rect.w as f32 / 512.0,
                    h: rect.h as f32 / 512.0,
                })
                .dest(Vec2::new(p.x as f32, p.y as f32));
            canvas.draw(ggez_image, draw_params);
        }
        canvas
            .finish(ctx)
            .wrap_err("Failed to draw encounter background")?;
        ctx.gfx.end_frame()?;
        Ok(canvas_image)
    }
}

pub struct EncounterScene<'a> {
    pub world: World,
    pub dispatcher: Dispatcher<'a, 'a>,
    pub background: Image,
    pub palette: Vec<piv::Colour>,
}

impl<'a> EncounterScene<'a> {
    fn update_controllers(&mut self, input: &input::InputState) {
        let entities = self.world.entities();
        let mut controllers = self.world.write_storage::<Controller>();
        for (_e, controller) in (&*entities, &mut controllers).join() {
            controller.x = input.get_axis_raw(controller.x_axis) as i32;
            controller.y = input.get_axis_raw(controller.y_axis) as i32;
            controller.fire = input.get_button_down(controller.button);
        }
    }
}

impl<'a> scenestack::Scene<game::Game, input::InputEvent> for EncounterScene<'a> {
    fn update(&mut self, game: &mut game::Game, _ctx: &mut ggez::Context) -> scenes::FSceneSwitch {
        self.world.maintain();
        self.update_controllers(&game.input);
        self.dispatcher.dispatch_par(&self.world);
        return scenestack::SceneSwitch::None;
    }

    fn draw(&mut self, game: &mut game::Game, ctx: &mut ggez::Context) -> ggez::GameResult<()> {
        let mut canvas = Canvas::from_frame(ctx, Option::None);
        canvas.set_sampler(Sampler::nearest_clamp());
        canvas.set_screen_coordinates(Rect::new(0., 0., 320., 200.));
        canvas.draw(&self.background, DrawParam::default());

        let position_storage = self.world.read_storage::<Position>();
        let draw_storage = self.world.read_storage::<Draw>();
        let entities = self.world.entities();
        let mut storage = (&position_storage, &draw_storage, &entities)
            .join()
            .collect::<Vec<_>>();

        for (position, draw, entity) in storage {
            let images: Vec<&AnimationImage> = draw.frame.images.iter().collect();
            for image in images {
                let atlas = game.assets.atlases.get(&image.sheet).unwrap();
                let atlas_dimension = atlas.image.width;
                let ggez_image = match game.assets.images.entry(image.sheet.clone()) {
                    Occupied(i) => i.into_mut(),
                    Vacant(i) => i.insert(graphics::Image::from_pixels(
                        ctx,
                        &atlas.image.to_rgba8(&self.palette),
                        graphics::ImageFormat::Rgba8UnormSrgb,
                        atlas_dimension as u32,
                        atlas_dimension as u32,
                    )),
                };
                let rect = atlas.rects[image.image];
                let texture_size = atlas.image.width as f32;
                let draw_params = graphics::DrawParam::default()
                    .src(graphics::Rect {
                        x: rect.x as f32 / texture_size,
                        y: rect.y as f32 / texture_size,
                        w: rect.w as f32 / texture_size,
                        h: rect.h as f32 / texture_size,
                    })
                    .dest(Vec2::new(
                        (position.x as i32 + (draw.direction as i32 * image.x)) as f32,
                        (position.y as i32 + image.y) as f32,
                    ))
                    .scale(Vec2::new(draw.direction as i32 as f32, 1.0));
                canvas.draw(ggez_image, draw_params);
            }
        }

        canvas.finish(ctx)?;
        Ok(())
    }

    fn name(&self) -> &str {
        "Encounter"
    }

    fn input(&mut self, _game: &mut game::Game, _event: input::InputEvent, _started: bool) {}
}
