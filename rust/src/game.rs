use std::collections::{HashMap, HashSet};

use failure::Error;
use ggez::Context;
use specs::World;
use warmy::{LogicalKey, Store, StoreOpt};

use crate::animation::{Frame, Sprite, SpriteData};
use crate::combat::components::{
    AnimationState, Body, Controller, Draw, Intent, Position, State, TouchingBoundary, Velocity,
    WalkingState, Weapon,
};
use crate::input;
use crate::manager::GameYaml;
use crate::objects::TextureAtlas;
use crate::rect::Rect;

#[derive(Debug, Default, Clone)]
pub struct ImageMetadata {
    pub data: HashMap<String, Vec<Rect>>,
}

#[derive(Debug, Default, Clone)]
pub struct EncounterTextures {
    pub data: HashMap<String, TextureAtlas>,
}

pub struct Game {
    pub input: input::InputState,
    pub input_binding: input::InputBinding,
    pub store: Store<Context>,
    pub world: World,
}

impl Game {
    pub fn new(ctx: &mut Context, entity_names: &[&str]) -> Result<Game, Error> {
        let mut store: Store<Context> = Store::new(StoreOpt::default())?;
        let mut world = World::new();
        world.register::<AnimationState>();
        world.register::<Body>();
        world.register::<Controller>();
        world.register::<Draw>();
        world.register::<Intent>();
        world.register::<Position>();
        world.register::<TouchingBoundary>();
        world.register::<State>();
        world.register::<Velocity>();
        world.register::<WalkingState>();
        world.register::<Weapon>();

        let entities_yaml =
            store.get::<_, GameYaml>(&warmy::LogicalKey::new("/entities.yaml"), ctx)?;

        let mut sprites: HashMap<String, Sprite> = HashMap::new();
        let mut atlas_names: HashSet<String> = HashSet::new();
        for name in entity_names {
            let yaml_borrow = &entities_yaml.borrow();
            let yaml_file = yaml_borrow.yaml[name].as_str().unwrap();
            let entity_yaml = store.get::<_, Sprite>(&warmy::LogicalKey::new(yaml_file), ctx)?;
            sprites.insert(name.to_string(), (*entity_yaml.borrow()).clone());

            for i in entity_yaml
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
        world.add_resource(SpriteData { sprites });

        let mut image_sizes: HashMap<String, Vec<Rect>> = HashMap::new();
        let mut texture_atlases: HashMap<String, TextureAtlas> = HashMap::new();
        for atlas_name in atlas_names {
            let atlas = store
                .get::<_, TextureAtlas>(&LogicalKey::new(atlas_name.clone()), ctx)
                .unwrap();
            image_sizes.insert(atlas_name.clone(), atlas.borrow().rects.clone());
            texture_atlases.insert(atlas_name.clone(), atlas.borrow().clone());
        }
        world.add_resource(ImageMetadata { data: image_sizes });
        world.add_resource(EncounterTextures {
            data: texture_atlases,
        });

        Ok(Game {
            input: input::InputState::new(),
            input_binding: input::create_input_binding(),
            store,
            world,
        })
    }
}
