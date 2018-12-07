use specs::{Read, ReadStorage, System, WriteStorage};

use crate::animation::{ImageType, SpriteData};
use crate::combat::components::{Body, Draw, Position, State, Weapon};
use crate::files::collide::CollisionBoxes;

pub struct UpdateBoundingBoxes;

impl<'a> System<'a> for UpdateBoundingBoxes {
    type SystemData = (
        Read<'a, CollisionBoxes>,
        Read<'a, SpriteData>,
        ReadStorage<'a, Draw>,
        ReadStorage<'a, Position>,
        ReadStorage<'a, State>,
        WriteStorage<'a, Body>,
        WriteStorage<'a, Weapon>,
    );

    fn run(
        &mut self,
        (collision_boxes, sprite_data, draw, position, state, mut body, mut weapon): Self::SystemData,
    ) {
        use specs::Join;
        let collision_data = &collision_boxes.data;
        let sprites = &sprite_data.sprites;
        for (draw, position, state, body, weapon) in
            (&draw, &position, &state, &mut body, &mut weapon).join()
        {
            for image in draw.frame.images.iter() {
                match image.image_type {
                    ImageType::Collider => {
                        println!("{:?}", image);
                    }
                    _ => (),
                }
            }
        }
    }
}
