//! Typedefs for input shortcuts.
use ggez::event::*;
use ggez::input::keyboard::KeyCode;
use ggez_goodies::input;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Button {
    Fire1,
    Fire2,
    Fire3,
    Fire4,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Axis {
    Vert1,
    Horz1,

    Vert2,
    Horz2,

    Vert3,
    Horz3,

    Vert4,
    Horz4,
}

pub type InputBinding = input::InputBinding<Axis, Button>;
pub type InputEvent = input::InputEffect<Axis, Button>;
pub type InputState = input::InputState<Axis, Button>;

/// Create the default keybindings for our input state.
pub fn create_input_binding() -> input::InputBinding<Axis, Button> {
    input::InputBinding::new()
        .bind_key_to_axis(KeyCode::Up, Axis::Vert1, false)
        .bind_key_to_axis(KeyCode::Down, Axis::Vert1, true)
        .bind_key_to_axis(KeyCode::Left, Axis::Horz1, false)
        .bind_key_to_axis(KeyCode::Right, Axis::Horz1, true)
        .bind_key_to_button(KeyCode::Space, Button::Fire1)
        // player 2
        .bind_key_to_axis(KeyCode::W, Axis::Vert2, false)
        .bind_key_to_axis(KeyCode::S, Axis::Vert2, true)
        .bind_key_to_axis(KeyCode::A, Axis::Horz2, false)
        .bind_key_to_axis(KeyCode::D, Axis::Horz2, true)
        .bind_key_to_button(KeyCode::LControl, Button::Fire2)
        //player 3
        .bind_key_to_axis(KeyCode::I, Axis::Vert3, false)
        .bind_key_to_axis(KeyCode::K, Axis::Vert3, true)
        .bind_key_to_axis(KeyCode::J, Axis::Horz3, false)
        .bind_key_to_axis(KeyCode::L, Axis::Horz3, true)
        .bind_key_to_button(KeyCode::G, Button::Fire3)
        //player 4
        .bind_key_to_axis(KeyCode::Numpad8, Axis::Vert4, false)
        .bind_key_to_axis(KeyCode::Numpad5, Axis::Vert4, true)
        .bind_key_to_axis(KeyCode::Numpad4, Axis::Horz4, false)
        .bind_key_to_axis(KeyCode::Numpad6, Axis::Horz4, true)
        .bind_key_to_button(KeyCode::NumpadEnter, Button::Fire4)
}
