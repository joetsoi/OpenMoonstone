use ggez::graphics::{DrawMode, Drawable, MeshBuilder, Point2};
use ggez::{graphics, timer, Context, GameResult};
use ggez_goodies::scene;
use std::time::Duration;

use crate::game::Game;
use crate::input::InputEvent;
use crate::scenes::FSceneSwitch;

#[derive(Debug)]
pub enum FadeStyle {
    In,
    Out,
}

pub struct Fade {
    pub start_time: Duration,
    pub duration: Duration,
    pub time_used: Duration,
    pub style: FadeStyle,
    done: bool,
    fade_start: u32,
    update_run: bool,
    ticks: u32,
}

impl scene::Scene<Game, InputEvent> for Fade {
    fn update(&mut self, game: &mut Game, ctx: &mut Context) -> FSceneSwitch {
        if !self.update_run {
            self.update_run = true;
        }
        if self.done {
            match self.style {
                FadeStyle::In => scene::SceneSwitch::Pop,
                FadeStyle::Out => scene::SceneSwitch::PopMultiple(2),
            }
        } else {
            scene::SceneSwitch::None
        }
    }

    fn draw(&mut self, game: &mut Game, ctx: &mut Context) -> GameResult<()> {
        // println!("draw transition");
        // TODO fix this when context is passed to update.
        let time_since_start = timer::get_time_since_start(ctx);
        if self.update_run && self.ticks < self.fade_start {
            self.ticks += 1;
            self.start_time = time_since_start;
        }
        let time_passed = time_since_start - self.start_time;
        let time_passed = timer::duration_to_f64(time_passed);
        let alpha = match self.style {
            FadeStyle::In => {
                let mut alpha = 1.0 - time_passed / timer::duration_to_f64(self.duration);
                if alpha < 0.0 {
                    alpha = 0.0;
                }
                alpha
            }
            FadeStyle::Out => {
                let mut alpha = time_passed / timer::duration_to_f64(self.duration);
                // if alpha < 1.0 {
                //     alpha = 1.0;
                // }
                alpha
            }
        };
        graphics::set_color(ctx, graphics::Color::new(0.0, 0.0, 0.0, alpha as f32))?;
        graphics::rectangle(
            ctx,
            DrawMode::Fill,
            graphics::Rect {
                x: 0.0,
                y: 0.0,
                w: 320.0 * 3.0,
                h: 200.0 * 3.0,
            },
        );
        graphics::set_color(ctx, graphics::Color::new(1.0, 1.0, 1.0, 1.0))?;
        if self.update_run && self.start_time + self.duration < timer::get_time_since_start(ctx) {
            self.done = true;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "Fade in"
    }

    fn input(&mut self, _gameworld: &mut Game, _event: InputEvent, _started: bool) {}

    fn draw_previous(&self) -> bool {
        true
    }
}

impl Fade {
    pub fn new(duration: u64, fade_start: u32, style: FadeStyle) -> Self {
        Fade {
            start_time: Duration::new(0, 0),
            duration: Duration::from_millis(duration),
            time_used: Duration::new(0, 0),
            style,
            done: false,
            fade_start: fade_start,
            update_run: false,
            ticks: 0,
        }
    }
}
