#![feature(rust_2018_preview)]
#![warn(rust_2018_idioms)]

use std::env;

use ggez::conf;
use ggez::event;
use ggez::graphics;
use ggez::graphics::Color;
use ggez::graphics::Image;
use ggez::timer;
use ggez::{Context, GameResult};
use image::{ImageBuffer, RgbaImage};

use openmoonstone::objects::Rect;

struct MainState {
    image: Image,
    test: Image,
    rect: Rect,
}

impl event::EventHandler for MainState {
    fn update(&mut self, ctx: &mut Context) -> GameResult<()> {
        const DESIRED_FPS: u32 = 1000 / (1193182 / 21845 * 2);
        while timer::check_update_time(ctx, DESIRED_FPS) {
            //println!("Delta frame time: {:?} ", timer::get_delta(ctx));
            //println!("Average FPS: {}", timer::get_fps(ctx));
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        graphics::set_background_color(ctx, Color::from((0, 0, 0, 255)));
        graphics::clear(ctx);

        let dest_point = graphics::Point2::new(0.0, 0.0);
        graphics::draw_ex(
            ctx,
            &self.image,
            graphics::DrawParam {
                dest: dest_point,
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;
        graphics::draw_ex(
            ctx,
            &self.test,
            graphics::DrawParam {
                src: graphics::Rect {
                    x: self.rect.x as f32 / 512.0,
                    y: self.rect.y as f32 / 512.0,
                    w: self.rect.w as f32 / 512.0,
                    h: self.rect.h as f32 / 512.0,
                },
                dest: dest_point,
                scale: graphics::Point2::new(3.0, 3.0),
                ..Default::default()
            },
        )?;
        graphics::present(ctx);

        timer::yield_now();
        Ok(())
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let ob = &args[2];

    let c = conf::Conf::new();
    let ctx = &mut Context::load_from_conf("openmoonstone", "joetsoi", c).unwrap();
    graphics::set_default_filter(ctx, graphics::FilterMode::Nearest);
    let piv = openmoonstone::piv::PivImage::from_file(filename).unwrap();
    let ob = openmoonstone::objects::ObjectsFile::from_file(ob).unwrap();
    //let image = Image::from_rgba8(ctx, 320, 200, &a.into_raw()).unwrap();

    //let mut packer =  TexturePacker::<MemoryRGBA8Texture, RGBA8>::new_skyline(config);
    let atlas = ob.to_texture_atlas();
    //let mut a: RgbaImage = ImageBuffer::from_raw(512, 512, atlas.image.to_rgba8(&piv.palette)).unwrap();
    //a.save("test.png");

    let background = Image::from_rgba8(ctx, 320, 200, &piv.to_rgba8()).unwrap();
    let image = Image::from_rgba8(ctx, 512, 512, &atlas.image.to_rgba8(&piv.palette)).unwrap();


    let im1 = &ob.images[0];
    let test = Image::from_rgba8(
        ctx,
        im1.width as u16,
        im1.height as u16,
        &im1.to_rgba8(&piv.palette),
    ).unwrap();

    let mut state = MainState {
        image: background,
        test: image,
        rect: atlas.rects[73],
    };
    event::run(ctx, &mut state).unwrap();
}
