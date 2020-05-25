use std::collections::hash_map::Entry::{Occupied, Vacant};

use ggez::nalgebra::{Point2, Vector2};
use ggez::{graphics, Context, GameResult};
use specs::{Join, World, WorldExt};
use warmy::SimpleKey;

use crate::animation::{Image, ImageType};
use crate::combat::components::{Draw, Palette, Position};
use crate::components::RenderOrder;
use crate::game::Game;
use crate::objects::TextureAtlas;
use crate::piv::Colour;

pub fn draw_entities(
    specs_world: &World,
    default_palette: &[Colour],
    background: Option<&graphics::Canvas>,
    game: &mut Game,
    ctx: &mut Context,
) -> GameResult<()> {
    let render_order_storage = specs_world.read_storage::<RenderOrder>();
    let position_storage = specs_world.read_storage::<Position>();
    let draw_storage = specs_world.read_storage::<Draw>();
    let entities = specs_world.entities();

    let palette_storage = specs_world.read_storage::<Palette>();

    let mut storage = (
        &render_order_storage,
        &position_storage,
        &draw_storage,
        &entities,
    )
        .join()
        .collect::<Vec<_>>();
    storage.sort_by(|&a, &b| a.0.depth.cmp(&b.0.depth));

    for (_, position, draw, entity) in storage {
        let images: Vec<&Image> = if game.gore_on {
            draw.frame.images.iter().collect()
        } else {
            draw.frame.images.iter().filter(|i| !i.is_blood()).collect()
        };
        for image in images {
            let atlas = game
                .store
                .get::<TextureAtlas>(&SimpleKey::from(image.sheet.as_str()), ctx)
                // TODO fix error handling, make this ?
                .expect("error loading texture atlas when drawing");

            let atlas_dimension = atlas.borrow().image.width as u32;

            let palette: Option<&Palette> = palette_storage.get(entity);
            let image_name = match palette {
                None => image.sheet.clone(),
                Some(palette) => format!("{}-{}", &image.sheet, &palette.name),
            };

            let p = palette.map_or(default_palette, |p| &p.palette[..]);
            let ggez_image = match game.images.entry(image_name) {
                Occupied(i) => i.into_mut(),
                Vacant(i) => i.insert(
                    graphics::Image::from_rgba8(
                        ctx,
                        atlas_dimension as u16,
                        atlas_dimension as u16,
                        &atlas.borrow().image.to_rgba8(p),
                    )
                    .unwrap(),
                ),
            };

            let rect = atlas.borrow().rects[image.image];
            let texture_size = atlas.borrow().image.width as f32;
            let draw_params = graphics::DrawParam::default()
                .src(graphics::Rect {
                    x: rect.x as f32 / texture_size,
                    y: rect.y as f32 / texture_size,
                    w: rect.w as f32 / texture_size,
                    h: rect.h as f32 / texture_size,
                })
                .dest(Point2::new(
                    (position.x as i32 + (draw.direction as i32 * image.x)) as f32,
                    (position.y as i32 + image.y) as f32,
                ))
                .scale(Vector2::new(draw.direction as i32 as f32, 1.0));

            graphics::draw(ctx, ggez_image, draw_params)?;
            if let ImageType::BloodStain = image.image_type {
                if let Some(b) = background {
                    graphics::pop_transform(ctx);
                    graphics::apply_transformations(ctx)?;

                    graphics::set_canvas(ctx, Some(&*b));
                    graphics::draw(ctx, ggez_image, draw_params)?;
                    graphics::set_canvas(ctx, None);

                    let scale_matrix = graphics::DrawParam::default()
                        .scale(game.screen_scale)
                        .to_matrix();
                    graphics::push_transform(ctx, Some(scale_matrix));
                    graphics::apply_transformations(ctx)?;
                }
            }
        }
    }
    Ok(())
}
