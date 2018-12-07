use std::collections::HashMap;

use failure::Error;
use ggez::Context;
use specs::World;
use warmy::{Store, StoreOpt};

use crate::animation::{Sprite, SpriteData};
use crate::combat::components::{
    AnimationState, AttackCollider, Collision, Controller, Draw, Intent, Position, State,
    TouchingBoundary, Velocity, WalkingState,
};
use crate::input;
use crate::manager::GameYaml;

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
        world.register::<AttackCollider>();
        world.register::<AnimationState>();
        world.register::<Collision>();
        world.register::<Controller>();
        world.register::<Draw>();
        world.register::<Intent>();
        world.register::<Position>();
        world.register::<TouchingBoundary>();
        world.register::<State>();
        world.register::<Velocity>();
        world.register::<WalkingState>();

        let entities_yaml =
            store.get::<_, GameYaml>(&warmy::LogicalKey::new("/entities.yaml"), ctx)?;

        let mut sprites: HashMap<String, Sprite> = HashMap::new();
        for name in entity_names {
            let yaml_borrow = &entities_yaml.borrow();
            let yaml_file = yaml_borrow.yaml[name].as_str().unwrap();
            let entity_yaml = store.get::<_, Sprite>(&warmy::LogicalKey::new(yaml_file), ctx)?;
            sprites.insert(name.to_string(), (*entity_yaml.borrow()).clone());
        }
        world.add_resource(SpriteData { sprites });

        Ok(Game {
            input: input::InputState::new(),
            input_binding: input::create_input_binding(),
            store,
            world,
        })
    }
}
