#![feature(rust_2018_preview)]
#![warn(rust_2018_idioms)]

use std::env;
use std::path::Path;
use std::time::Duration;

use ggez::conf;
use ggez::event;
use ggez::filesystem;
use ggez::graphics;
use ggez::graphics::Color;
use ggez::graphics::Image;
use ggez::timer;
use ggez::{Context, GameResult};
use image::{ImageBuffer, RgbaImage};
use serde_yaml;
use serde_yaml::Value;
use specs::world::Builder;
use specs::RunNow;
use specs::World;

use openmoonstone::combat::components::{Draw, Position};
use openmoonstone::combat::systems::{Movement, Renderer};
use openmoonstone::objects::Rect;

struct MainState {
    image: Image,
    batch: graphics::spritebatch::SpriteBatch,
    rects: Vec<Rect>,
    encounter: World,
    systems: Systems,
}

struct Systems {
    movement: Movement,
    renderer: Renderer,
}

impl event::EventHandler for MainState {
    fn update(&mut self, ctx: &mut Context) -> GameResult<()> {
        const DESIRED_FPS: u32 = 1000 / (1193182 / 21845 * 2);
        while timer::check_update_time(ctx, DESIRED_FPS) {
            self.systems.movement.run_now(&self.encounter.res)
            // println!("Delta frame time: {:?} ", timer::get_delta(ctx));
            // println!("Average FPS: {}", timer::get_fps(ctx));
        }
        timer::sleep(Duration::from_millis(109));
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
        self.systems.renderer.run_now(&self.encounter.res);

        //let banner = &self.rects[73];
        //self.batch.add(graphics::DrawParam {
        //    src: graphics::Rect {
        //        x: banner.x as f32 / 512.0,
        //        y: banner.y as f32 / 512.0,
        //        w: banner.w as f32 / 512.0,
        //        h: banner.h as f32 / 512.0,
        //    },
        //    dest: graphics::Point2::new(5.0, 20.0),
        //    //scale: graphics::Point2::new(3.0, 3.0),
        //    ..Default::default()
        //});

        //let copyright = &self.rects[74];
        //self.batch.add(graphics::DrawParam {
        //    src: graphics::Rect {
        //        x: copyright.x as f32 / 512.0,
        //        y: copyright.y as f32 / 512.0,
        //        w: copyright.w as f32 / 512.0,
        //        h: copyright.h as f32 / 512.0,
        //    },
        //    dest: graphics::Point2::new(22.0, 181.0),
        //    //scale: graphics::Point2::new(3.0, 3.0),
        //    ..Default::default()
        //});

        //let rights = &self.rects[75];
        //self.batch.add(graphics::DrawParam {
        //    src: graphics::Rect {
        //        x: rights.x as f32 / 512.0,
        //        y: rights.y as f32 / 512.0,
        //        w: rights.w as f32 / 512.0,
        //        h: rights.h as f32 / 512.0,
        //    },
        //    dest: graphics::Point2::new(110.0, 190.0),
        //    //scale: graphics::Point2::new(3.0, 3.0),
        //    ..Default::default()
        //});
        //graphics::draw_ex(
        //    ctx,
        //    &self.batch,
        //    graphics::DrawParam {
        //        dest: dest_point,
        //        scale: graphics::Point2::new(3.0, 3.0),
        //        ..Default::default()
        //    },
        //)?;
        self.batch.clear();
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

    let file = ctx.filesystem.open("/files.yaml").unwrap();
    let yaml: Value = serde_yaml::from_reader(file).unwrap();

    let background = &yaml["scenes"][filename].as_str().unwrap();
    let mut file = ctx
        .filesystem
        .open(Path::new("/moonstone/").join(background))
        .unwrap();
    let piv = openmoonstone::piv::PivImage::from_reader(&mut file).unwrap();

    let objects = &yaml["objects"];
    let kn4 = &objects[ob]; //.unwrap().as_str().unwrap();
                            //println!("{:?}", );
    let mut file = ctx
        .filesystem
        .open(Path::new("/moonstone/").join(&kn4["file"].as_str().unwrap()))
        .unwrap();
    let ob = openmoonstone::objects::ObjectsFile::from_reader(&mut file).unwrap();

    let texture_size: u32 = kn4["texture_size"].as_u64().unwrap() as u32;
    let atlas = ob
        .to_texture_atlas(texture_size as i32)
        .expect("texture size too small");

    let mut a: RgbaImage = ImageBuffer::from_raw(
        texture_size,
        texture_size,
        atlas.image.to_rgba8(&piv.palette),
    ).unwrap();
    a.save("test.png");

    let background = Image::from_rgba8(ctx, 320, 200, &piv.to_rgba8()).unwrap();
    let image = Image::from_rgba8(
        ctx,
        texture_size as u16,
        texture_size as u16,
        &atlas.image.to_rgba8(&piv.palette),
    ).unwrap();
    let test = image.clone();
    let batch = graphics::spritebatch::SpriteBatch::new(image);

    let im1 = &ob.images[0];
    let test = Image::from_rgba8(
        ctx,
        im1.width as u16,
        im1.height as u16,
        &im1.to_rgba8(&piv.palette),
    ).unwrap();

    let mut encounter = World::new();
    encounter.register::<Position>();
    //let knight = encounter.create_entity().with(Position { x: 100, y: 100 }).with(Draw { sprite_sheet: batch, rects: vec![73, 74, 75]}).build();
    let knight = encounter
        .create_entity()
        .with(Position { x: 100, y: 100 })
        .build();
    let movement = Movement;
    let renderer = Renderer;
    let systems = Systems {
        movement: movement,
        renderer: renderer,
    };

    let mut state = MainState {
        image: background,
        batch: batch,
        rects: atlas.rects,
        encounter: encounter,
        systems: systems,
    };

    event::run(ctx, &mut state).unwrap();
}
