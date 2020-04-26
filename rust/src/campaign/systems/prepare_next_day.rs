use specs::{Entities, Join, ReadExpect, ReadStorage, System, WriteExpect, WriteStorage};

use crate::animation::SpriteData;
use crate::campaign::components::map_intent::MapCommand;
use crate::campaign::components::{Endurance, MapIntent};
use crate::combat::components::{Controller, Draw};
use crate::input::{Axis, Button};
use crate::scenes::map::{OrderedEntities, TurnOver};

pub struct PrepareNextDay;

impl<'a> System<'a> for PrepareNextDay {
    type SystemData = (
        ReadExpect<'a, SpriteData>,
        WriteExpect<'a, OrderedEntities>,
        WriteExpect<'a, TurnOver>,
        WriteStorage<'a, Endurance>,
        WriteStorage<'a, Draw>,
        WriteStorage<'a, Controller>,
        Entities<'a>,
    );

    fn run(
        &mut self,
        (
            sprite_data,
            mut ordered_entities,
            mut turn_over,
            mut endurance,
            mut draw_storage,
            mut controller_storage,
            entities,
        ): Self::SystemData,
    ) {
        if turn_over.0 == true {
            for (endurance) in (&mut endurance).join() {
                endurance.used = 0;
            }
            ordered_entities.reset();
            let first_player = ordered_entities
                .current()
                .and_then(|id| Some(entities.entity(*id)));
            println!("{:?}", first_player);
            if let Some(player) = first_player {
                controller_storage.insert(
                    player,
                    Controller {
                        x_axis: Axis::Horz1,
                        y_axis: Axis::Vert1,
                        button: Button::Fire1,
                        ..Default::default()
                    },
                );

                let sprites = &sprite_data.sprites;
                let draw = draw_storage
                    .get_mut(player)
                    .unwrap_or_else(|| panic!("player doesn't have a draw component"));
                let animation = draw.animation.as_str();
                let sprite_resource = sprites.get(&draw.resource_name);

                if let Some(sprite) = sprite_resource {
                    let animation = sprite
                        .animations
                        .get("selected")
                        .unwrap_or_else(|| panic!("{} not found in ron", animation));

                    // adjust this for the dragon, all other map figures are unanimated
                    draw.frame = animation.frames[0usize].clone();
                }
            }
        }
    }
}

pub struct NextPlayer;

impl<'a> System<'a> for NextPlayer {
    type SystemData = (
        ReadExpect<'a, SpriteData>,
        WriteExpect<'a, OrderedEntities>,
        WriteExpect<'a, TurnOver>,
        ReadStorage<'a, Endurance>,
        WriteStorage<'a, Draw>,
        WriteStorage<'a, Controller>,
        WriteStorage<'a, MapIntent>,
        Entities<'a>,
    );

    fn run(
        &mut self,
        (
            sprite_data,
            mut ordering,
            mut turn_over,
            endurance_storage,
            mut draw_storage,
            mut controller_storage,
            mut intent_storage,
            entities,
        ): Self::SystemData,
    ) {
        let sprites = &sprite_data.sprites;
        let current_player = ordering.current().and_then(|id| Some(entities.entity(*id)));
        if let Some(player) = current_player {
            // let is_exhausted = endurance_storage
            //     .get(player)
            //     .and_then(|e| Some(e.used >= e.max))
            //     .unwrap_or(false);
            // if is_exhausted == true {
            if ordering.player_done == true {
                let draw = draw_storage
                    .get_mut(player)
                    .unwrap_or_else(|| panic!("player doesn't have a draw component"));
                let animation = draw.animation.as_str();
                let sprite_resource = sprites.get(&draw.resource_name);

                if let Some(sprite) = sprite_resource {
                    let animation = sprite
                        .animations
                        .get("unselected")
                        .unwrap_or_else(|| panic!("{} not found in ron", animation));

                    // adjust this for the dragon, all other map figures are unanimated
                    draw.frame = animation.frames[0usize].clone();
                }
                controller_storage.remove(player);
                let intent = intent_storage
                    .get_mut(player)
                    .unwrap_or_else(|| panic!("player doesn't have a map intent component"));
                intent.command = MapCommand::Idle;
                ordering.player_done = false;

                let next_player = ordering.next().and_then(|id| Some(entities.entity(id)));
                match next_player {
                    Some(player) => {
                        let draw = draw_storage
                            .get_mut(player)
                            .unwrap_or_else(|| panic!("player doesn't have a draw component"));
                        let animation = draw.animation.as_str();
                        let sprite_resource = sprites.get(&draw.resource_name);

                        if let Some(sprite) = sprite_resource {
                            let animation = sprite
                                .animations
                                .get("selected")
                                .unwrap_or_else(|| panic!("{} not found in ron", animation));

                            // adjust this for the dragon, all other map figures are unanimated
                            draw.frame = animation.frames[0usize].clone();
                        }
                        controller_storage.insert(
                            player,
                            Controller {
                                x_axis: Axis::Horz1,
                                y_axis: Axis::Vert1,
                                button: Button::Fire1,
                                ..Default::default()
                            },
                        );
                    }
                    None => {
                        turn_over.0 = true;
                    }
                }
            }
        }
    }
}
