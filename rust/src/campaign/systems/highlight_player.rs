// Highlights the active player on the map screen
use specs::{Join, ReadExpect, System, WriteStorage};

use crate::combat::components::Palette;
use crate::scenes::map::FlashingPalettes;

pub struct HighlightPlayer;

impl<'a> System<'a> for HighlightPlayer {
    type SystemData = (ReadExpect<'a, FlashingPalettes>, WriteStorage<'a, Palette>);
    fn run(&mut self, (flash, mut palette): Self::SystemData) {
        for mut palette in (&mut palette).join() {
            let mut i: usize = palette
                .name
                .parse::<usize>()
                // if we can't determine which palette we're on, just default
                // to the first palette in FlashingPalettes
                .unwrap_or(0) as usize;
            i = (i + 1) % flash.palettes.len();
            palette.name = i.to_string();
            palette.palette = flash.palettes[i].clone();
        }
    }
}
