use specs::{Entities, ReadStorage, System, WriteStorage};

use crate::combat::components::intent::AttackType;
use crate::combat::components::{Action, Command, DaggersInventory, Intent, State};

pub struct ActionSystem;

impl<'a> System<'a> for ActionSystem {
    type SystemData = (
        ReadStorage<'a, Intent>,
        WriteStorage<'a, DaggersInventory>,
        WriteStorage<'a, State>,
        Entities<'a>,
    );

    fn run(&mut self, (intent, mut dagger_storage, mut state, entities): Self::SystemData) {
        use specs::Join;

        for (intent, state, entity) in (&intent, &mut state, &*entities).join() {
            match intent.command {
                Command::Attack(AttackType::ThrowDagger) => match state.action {
                    Action::Idle | Action::Move { .. } => {
                        let daggers: Option<&mut DaggersInventory> = dagger_storage.get_mut(entity);

                        if let Some(daggers) = daggers {
                            if daggers.count > 0 {
                                state.action = Action::Attack(AttackType::ThrowDagger);
                                state.length = 0;
                                state.ticks = 0;
                                daggers.count -= 1;
                            }
                        }
                    }
                    _ => (),
                },
                Command::Attack(attack_type) => match state.action {
                    Action::Idle | Action::Move { .. } => {
                        state.action = Action::Attack(attack_type);
                        state.length = 0;
                        state.ticks = 0;
                    }
                    _ => (),
                },
                Command::Defend(defend_type) => match state.action {
                    Action::Idle | Action::Move { .. } => {
                        state.action = Action::Defend(defend_type);
                        state.length = 0;
                        state.ticks = 0;
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }
}

// impl<'a> ActionSystem {
//     fn create_dagger_components(&self, entity: &Entity, entities: &Entities, updater: &Read<'a, LazyUpdate>) {
//         if let Some(position) = position {
//             let dagger = entities.create();
//             // position_storage.insert(
//             //     dagger,
//             //     Position {
//             //         x: position.x + 5,
//             //         y: position.y,
//             //     },
//             // );
//             // // // velocity_storage.insert(dagger, Velocity {});
//             // draw_storage.insert(dagger, Draw {});
//             // animation_storage.insert(dagger, AnimationState { frame_number: 0 });
//             // weapon_storage.insert(
//             //     dagger,
//             //     Weapon {
//             //         ..Default::default()
//             //     },
//             // );
//             // state_storage.insert(
//             //     dagger,
//             //     State {
//             //         action: Action::Idle,
//             //         direction: state.direction,
//             //         length: 0,
//             //         ticks: 0,
//             //     },
//             // );
//         }
//     }
// }
