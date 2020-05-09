// Highlights the active player on the map screen
use specs::{
    storage::ComponentEvent,
    BitSet,
    Join,
    ReadExpect,
    ReadStorage,
    ReaderId,
    System,
    SystemData,
    World,
    WriteStorage,
};

use crate::campaign::components::{Interactable, OnHoverImage};
use crate::combat::components::Draw;
use crate::rect::Rect;

pub struct HighlightOnHover;

impl<'a> System<'a> for HighlightOnHover {
    type SystemData = (
        ReadStorage<'a, Interactable>,
        ReadStorage<'a, OnHoverImage>,
        WriteStorage<'a, Draw>,
    );
    fn run(
        &mut self,
        (collided_storage, on_hover_image_storage, mut draw_storage): Self::SystemData,
    ) {
        for (collided, on_hover_image, draw) in (
            &collided_storage,
            &on_hover_image_storage,
            &mut draw_storage,
        )
            .join()
        {
            if let Some(hover) = &on_hover_image.hover {
                draw.frame.images.clear();
                draw.frame.images.push(hover.clone());
            }
        }
    }
}

#[derive(Default)]
pub struct DehighlightOnExit {
    pub dirty: BitSet,
    pub reader_id: Option<ReaderId<ComponentEvent>>,
}

impl<'a> System<'a> for DehighlightOnExit {
    type SystemData = (
        ReadStorage<'a, Interactable>,
        ReadStorage<'a, OnHoverImage>,
        WriteStorage<'a, Draw>,
    );

    fn run(
        &mut self,
        (interact_storage, on_hover_image_storage, mut draw_storage): Self::SystemData,
    ) {
        self.dirty.clear();
        let events = interact_storage
            .channel()
            .read(self.reader_id.as_mut().expect("ReaderId not found"));
        for event in events {
            if let ComponentEvent::Removed(id) = event {
                self.dirty.add(*id);
            };
        }
        for (on_hover_image, draw, _) in
            (&on_hover_image_storage, &mut draw_storage, &self.dirty).join()
        {
            draw.frame.images.clear();
            match &on_hover_image.image {
                Some(image) => draw.frame.images.push(image.clone()),
                None => (),
            }
        }
    }

    fn setup(&mut self, res: &mut World) {
        Self::SystemData::setup(res);
        self.reader_id = Some(WriteStorage::<Interactable>::fetch(&res).register_reader());
    }
}
