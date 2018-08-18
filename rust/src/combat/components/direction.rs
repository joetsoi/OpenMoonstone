#[derive(Debug, Copy, Clone)]
pub enum Direction {
    Left = -1,
    Right = 1,
}

impl Default for Direction {
    fn default() -> Direction {
        Direction::Right
    }
}
