//! Typedefs for input shortcuts.
use ggez::event::*;
use ggez_goodies::input;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Button {
    Fire1,
    Fire2,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Axis {
    Vert1,
    Horz1,

    Vert2,
    Horz2,
}

pub type InputBinding = input::InputBinding<Axis, Button>;
pub type InputEvent = input::InputEffect<Axis, Button>;
pub type InputState = input::InputState<Axis, Button>;

/// Create the default keybindings for our input state.
pub fn create_input_binding() -> input::InputBinding<Axis, Button> {
    input::InputBinding::new()
        .bind_key_to_axis(Keycode::Up, Axis::Vert1, false)
        .bind_key_to_axis(Keycode::Down, Axis::Vert1, true)
        .bind_key_to_axis(Keycode::Left, Axis::Horz1, false)
        .bind_key_to_axis(Keycode::Right, Axis::Horz1, true)
        .bind_key_to_button(Keycode::Space, Button::Fire1)
        // player 2
        .bind_key_to_axis(Keycode::W, Axis::Vert2, false)
        .bind_key_to_axis(Keycode::S, Axis::Vert2, true)
        .bind_key_to_axis(Keycode::A, Axis::Horz2, false)
        .bind_key_to_axis(Keycode::D, Axis::Horz2, true)
        .bind_key_to_button(Keycode::LCtrl, Button::Fire2)
}
