use specs::{ReadExpect, ReadStorage, System, WriteStorage};

use crate::animation::SpriteData;
use crate::combat::components::{AnimationState, Draw, State};

pub struct UpdateImage;

impl<'a> System<'a> for UpdateImage {
    type SystemData = (
        ReadExpect<'a, SpriteData>,
        WriteStorage<'a, Draw>,
        ReadStorage<'a, AnimationState>,
        WriteStorage<'a, State>,
    );

    fn run(&mut self, (sprite_data, mut draw, animation_state, mut state): Self::SystemData) {
        use specs::Join;
        let sprites = &sprite_data.sprites;
        // println!("{:?}", sprites);
        for (draw, animation_state, state) in (&mut draw, &animation_state, &mut state).join() {
            let animation = draw.animation.as_str();
            let sprite_resource = sprites.get(&draw.resource_name);
            if let Some(sprite) = sprite_resource {
                let animation = sprite
                    .animations
                    .get(animation)
                    .unwrap_or_else(|| panic!("{} not found in yaml", animation));
                match &animation.order {
                    None => {
                        draw.frame =
                            animation.frames[animation_state.frame_number as usize].clone();
                        draw.direction = state.direction;
                        state.length = animation.frames.len() as u32;
                    }
                    Some(order) => {
                        let frame_num: usize =
                            order[animation_state.frame_number as usize] as usize;
                        draw.frame = animation.frames[frame_num].clone();
                        draw.direction = state.direction;
                        state.length = order.len() as u32;
                    }
                }
            }
        }
    }
}
