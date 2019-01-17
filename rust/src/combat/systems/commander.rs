use specs::{ReadStorage, System, WriteStorage};

use crate::combat::components::intent::{AttackType, DefendType, XAxis, YAxis};
use crate::combat::components::{Command, Controller, Intent, State};

pub struct Commander;

impl<'a> System<'a> for Commander {
    type SystemData = (
        ReadStorage<'a, Controller>,
        ReadStorage<'a, State>,
        WriteStorage<'a, Intent>,
    );

    fn run(&mut self, (controller, state, mut intent): Self::SystemData) {
        use specs::Join;

        for (controller, state, intent) in (&controller, &state, &mut intent).join() {
            if controller.x == 0 && controller.y == 0 {
                intent.command = Command::Idle;
            } else if !controller.fire {
                let x = match controller.x {
                    -1 => XAxis::Left,
                    1 => XAxis::Right,
                    _ => XAxis::Centre,
                };
                let y = match controller.y {
                    -1 => YAxis::Up,
                    1 => YAxis::Down,
                    _ => YAxis::Centre,
                };
                intent.command = Command::Move { x, y };
            } else {
                let x = controller.x * state.direction as i32;
                let attack_type = match (x, controller.y) {
                    (-1, 1) => Command::Defend(DefendType::Block),
                    (-1, 0) => Command::Attack(AttackType::BackSwing),
                    (-1, -1) => Command::Attack(AttackType::ThrowDagger),

                    (0, 1) => Command::Defend(DefendType::Dodge),
                    (0, 0) => Command::Idle,
                    (0, -1) => Command::Attack(AttackType::Chop),

                    (1, 1) => Command::Attack(AttackType::Thrust),
                    (1, 0) => Command::Attack(AttackType::Swing),
                    (1, -1) => Command::Attack(AttackType::UpThrust),

                    (_, _) => Command::Idle,
                };
                intent.command = attack_type;
            }
        }
    }
}
