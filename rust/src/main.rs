extern crate openmoonstone;
extern crate ggez;

use std::env;
use std::path;
use ggez::conf;
use ggez::event;
use ggez::graphics;
use ggez::graphics::Image;
use ggez::graphics::Color;
use ggez::timer;
use ggez::{Context, GameResult};


struct MainState{
    image: Image,
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
            }
        )?;
        graphics::present(ctx);

        timer::yield_now();
        Ok(())
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];

    let c = conf::Conf::new();
    let ctx = &mut Context::load_from_conf("openmoonstone", "joetsoi", c).unwrap();
    ctx.print_resource_stats();
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let mut path = path::PathBuf::from(manifest_dir);
        path.push("resources");
        ctx.filesystem.mount(&path, true);
}
    let piv = openmoonstone::piv::PivImage::from_file(filename).unwrap();
    let image = Image::from_rgba8(ctx, 320, 200, &piv.to_rgba8()).unwrap();

    let mut state = MainState{
        image: image,
    };
    event::run(ctx, &mut state).unwrap();
}
