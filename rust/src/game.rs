use ggez::Context;
use specs::world;
use specs::{Dispatcher, DispatcherBuilder, Join, World};
use warmy::{Store, StoreOpt};

use crate::combat::components::{
    AnimationState, Controller, Draw, Facing, Intent, Position, TouchingBoundary, Velocity,
    WalkingState,
};
use crate::input;

pub struct Game {
    pub input: input::InputState,
    pub input_binding: input::InputBinding,
    pub store: Store<Context>,
    pub world: World,
}

impl Game {
    pub fn new(ctx: &Context) -> Game {
        let mut store: Store<Context> =
            Store::new(StoreOpt::default()).expect("store creation failed");
        let mut world = World::new();
        world.register::<AnimationState>();
        world.register::<Controller>();
        world.register::<Draw>();
        world.register::<Intent>();
        world.register::<Position>();
        world.register::<TouchingBoundary>();
        world.register::<Velocity>();
        world.register::<WalkingState>();
        Game {
            input: input::InputState::new(),
            input_binding: input::create_input_binding(),
            store: store,
            world: world,
        }
    }
}
