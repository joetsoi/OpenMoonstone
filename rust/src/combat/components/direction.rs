#[derive(Debug, Copy, Clone)]
pub enum Facing {
    Left = -1,
    Right = 1,
}

impl Default for Facing {
    fn default() -> Facing {
        Facing::Right
    }
}
