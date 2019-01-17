#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Facing {
    Left = -1,
    Right = 1,
}

impl Default for Facing {
    fn default() -> Facing {
        Facing::Right
    }
}

impl Facing {
    pub fn flip(self) -> Facing {
        let value = -(self as i32);
        match value {
            -1 => Facing::Left,
            1 => Facing::Right,
            _ => panic!("not a valid facing value, this should never happen"),
        }
    }
}
