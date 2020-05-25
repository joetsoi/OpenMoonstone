use std::cmp::min;

use specs::{
    storage::BTreeStorage,
    Builder,
    Component,
    Entities,
    Entity,
    EntityBuilder,
    LazyUpdate,
    Read,
    World,
    WorldExt,
};
use specs_derive::*;

use super::{
    AnimationState,
    Body,
    DaggersInventory,
    Draw,
    Facing,
    Health,
    Intent,
    MustLive,
    Palette,
    Position,
    State,
    Velocity,
    WalkingState,
    Weapon,
};
use crate::animation::Frame;
use crate::components::RenderOrder;
use crate::piv::Colour;

/// Non consuming (but mutating) builder for Entities
/// This provides a more game oriented interface for building entities
/// e.g
///   - build a combatant as a black knight
///   - armed with a sword of sharpness
///   - controlled by the AI
///
/// Since this is a non-consuming builder it can be used multiple times to
/// spawn many types of the same entity
#[derive(Clone, Debug, Default)]
pub struct CharacterTemplate {
    resource: String,
    position: Position,
    state: State,
    palette: Palette,
    draw: Draw,
}

impl CharacterTemplate {
    pub fn build_entity<'a>(&mut self, world: &'a mut World) -> EntityBuilder<'a> {
        world
            .create_entity()
            .with(MustLive {})
            .with(self.position.clone())
            .with(Intent {
                ..Default::default()
            })
            .with(WalkingState {
                ..Default::default()
            })
            .with(Velocity {
                ..Default::default()
            })
            .with(AnimationState {
                ..Default::default()
            })
            .with(RenderOrder {
                ..Default::default()
            })
            .with(self.draw.clone())
            .with(self.palette.clone())
            .with(self.state.clone())
            .with(Health {
                ..Default::default()
            })
            .with(Body {
                ..Default::default()
            })
            .with(Weapon {
                ..Default::default()
            })
            .with(DaggersInventory {
                ..Default::default()
            })
    }

    pub fn build_from_template<'a>(&self, builder: impl Builder) -> impl Builder {
        builder
            .with(MustLive {})
            .with(self.position.clone())
            .with(Intent {
                ..Default::default()
            })
            .with(WalkingState {
                ..Default::default()
            })
            .with(Velocity {
                ..Default::default()
            })
            .with(AnimationState {
                ..Default::default()
            })
            .with(RenderOrder {
                ..Default::default()
            })
            .with(self.draw.clone())
            .with(self.palette.clone())
            .with(self.state.clone())
            .with(Health {
                ..Default::default()
            })
            .with(Body {
                ..Default::default()
            })
            .with(Weapon {
                ..Default::default()
            })
            .with(DaggersInventory {
                ..Default::default()
            })
    }

    pub fn position<'a>(&'a mut self, x: i32, y: i32) -> &'a mut Self {
        self.position.x = x;
        self.position.y = y;
        self
    }

    pub fn draw<'a>(
        &'a mut self,
        frame: &Frame,
        animation: &str,
        direction: Facing,
    ) -> &'a mut Self {
        self.draw = Draw {
            frame: frame.clone(),
            animation: animation.to_string(),
            resource_name: self.resource.clone(),
            direction: direction,
        };
        self
    }

    pub fn state<'a>(&'a mut self, direction: Facing) -> &'a mut Self {
        self.state.direction = direction;
        self
    }

    pub fn palette<'a>(&'a mut self, name: &str, colours: &[Colour]) -> &'a mut Self {
        self.palette.name = name.to_string();
        self.palette.palette.splice(.., colours.to_vec());
        self
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SpawnPoint {
    x: i32,
    y: i32,
    direction: Facing,
}

#[derive(Clone, Debug, Component)]
#[storage(BTreeStorage)]
pub struct SpawnPool {
    pub character: CharacterTemplate,
    pub remaining: usize,
    pub max_active: usize,
    pub active: Vec<Entity>,
    pub spawn_points: Vec<SpawnPoint>,
}

impl Default for SpawnPool {
    fn default() -> Self {
        SpawnPool {
            character: CharacterTemplate {
                resource: "knight".to_string(),
                ..Default::default()
            },
            remaining: 1,
            max_active: 1,
            active: Vec::new(),
            spawn_points: Vec::new(),
        }
    }
}

impl SpawnPool {
    pub fn new(resource: &str) -> Self {
        SpawnPool {
            character: CharacterTemplate {
                resource: resource.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn spawn<'a>(&mut self, world: &'a mut World) -> Option<EntityBuilder<'a>> {
        if self.remaining > 0 {
            self.remaining -= 1;
            Some(self.character.build_entity(world))
        } else {
            None
        }
    }

    pub fn spawn_lazy<'a>(&mut self, lazy: &Read<'a, LazyUpdate>, entities: &Entities<'a>) {
        let spaces = min(self.max_active - self.active.len(), self.remaining);
        for _ in 0..spaces {
            let builder = self
                .character
                .build_from_template(lazy.create_entity(&entities));
            builder.build();
        }
    }
}
