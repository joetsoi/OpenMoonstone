use std::collections::hash_map::Entry::{Occupied, Vacant};

use ggez::nalgebra::{Point2, Vector2};
use ggez::{graphics, Context, GameResult};
use specs::{Join, World, WorldExt};
use warmy::SimpleKey;

use crate::animation::{Image, ImageType};
use crate::combat::components::{Draw, Palette, Position};
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
    let position_storage = specs_world.read_storage::<Position>();
    let draw_storage = specs_world.read_storage::<Draw>();
    let entities = specs_world.entities();

    let palette_storage = specs_world.read_storage::<Palette>();

    let mut storage = (&position_storage, &draw_storage, &entities)
        .join()
        .collect::<Vec<_>>();
    storage.sort_by(|&a, &b| a.0.y.cmp(&b.0.y));
    storage.iter().map(|(position, draw, entity)| position);

    for (position, draw, entity) in storage {
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
            // TODO: change with palettes
            let palette: Option<&Palette> = palette_storage.get(entity);
            let ggez_image = match palette {
                None => match game.images.entry(image.sheet.clone()) {
                    Occupied(i) => i.into_mut(),
                    Vacant(i) => i.insert(
                        graphics::Image::from_rgba8(
                            ctx,
                            atlas_dimension as u16,
                            atlas_dimension as u16,
                            &atlas.borrow().image.to_rgba8(&default_palette),
                        )
                        .unwrap(),
                    ),
                },
                Some(palette) => {
                    let image_name = [image.sheet.clone(), palette.name.clone()].join("-");
                    match game.images.entry(image_name) {
                        Occupied(i) => i.into_mut(),
                        Vacant(i) => i.insert(
                            graphics::Image::from_rgba8(
                                ctx,
                                atlas_dimension as u16,
                                atlas_dimension as u16,
                                &atlas.borrow().image.to_rgba8(&palette.palette),
                            )
                            .unwrap(),
                        ),
                    }
                }
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
            // .scale(Vector2::new((draw.direction as i32 * 3) as f32, 3.0));
            // .dest(Point2::new(
            //     (position.x as i32 + (draw.direction as i32 * image.x)) as f32 * 3.0,
            //     (position.y as i32 + image.y) as f32 * 3.0,
            // ))
            // .scale(Vector2::new((draw.direction as i32 * 3) as f32, 3.0));
            graphics::draw(ctx, ggez_image, draw_params)?;
            if let ImageType::BloodStain = image.image_type {
                if let Some(b) = background {
                    graphics::pop_transform(ctx);
                    graphics::apply_transformations(ctx);

                    graphics::set_canvas(ctx, Some(&*b));
                    graphics::draw(ctx, ggez_image, draw_params)?;
                    graphics::set_canvas(ctx, None);

                    let scale_matrix = graphics::DrawParam::default()
                        .scale(game.screen_scale)
                        .to_matrix();
                    graphics::push_transform(ctx, Some(scale_matrix));
                    graphics::apply_transformations(ctx);
                }
            }
        }
    }
    Ok(())
}
