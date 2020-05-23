use super::components::{
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
    UnitType,
    Velocity,
    WalkingState,
    Weapon,
};
use crate::components::RenderOrder;
use specs::{Builder, EntityBuilder, World, WorldExt};

/// Non consuming (but mutating) builder for Entities
/// This provides a more game oriented interface for building entities
/// e.g
///   - build a combatant as a black knight
///   - armed with a sword of sharpness
///   - controlled by the AI
///
/// Since this is a non-consuming builder it can be used multiple times to
/// spawn many types of the same entity
#[derive(Default)]
pub struct CharacterTemplate {
    resource: String,
    position: Position,
}

impl CharacterTemplate {
    pub fn build_entity<'a>(&mut self, world: &'a mut World) -> EntityBuilder<'a> {
        world
            .create_entity()
            .with(UnitType {
                name: self.resource.clone(),
            })
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

    pub fn position<'a>(&'a mut self, x: i32, y: i32) -> &'a Self {
        self.position.x = x;
        self.position.y = y;
        self
    }

    // pub fn animation<'a>(&'a mut self, frame: Frame, animation: &str) {
    //     self
    // }
}

pub struct SpawnPoint {
    x: i32,
    y: i32,
    direction: Facing,
}

pub struct SpawnPool {
    pub character: CharacterTemplate,
    pub remaining: u32,
}

impl Default for SpawnPool {
    fn default() -> Self {
        SpawnPool {
            character: CharacterTemplate {
                resource: "knight".to_string(),
                position: Position { x: 0, y: 0 },
            },
            remaining: 1,
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
}
