use std::ops::Add;

#[derive(Default, Copy, Clone, Debug)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub fn intersects(&self, other: &Rect) -> bool {
        self.x < other.x + other.w
            && self.x + other.w > other.x
            && self.y < other.y + other.h
            && self.h + self.y > other.y
    }

    pub fn contains_point(&self, point: &Point) -> bool {
        point.x > self.x
            && point.x < self.x + self.w
            && point.y > self.y
            && point.y > self.y + self.h
    }
}

impl Add<Point> for Rect {
    type Output = Rect;

    fn add(self, other: Point) -> Rect {
        Rect {
            x: self.x + other.x,
            y: self.y + other.y,
            w: self.w,
            h: self.h,
        }
    }
}

impl Add<(u32, u32)> for Rect {
    type Output = Rect;

    fn add(self, other: (u32, u32)) -> Rect {
        Rect {
            x: self.x + other.0 as i32,
            y: self.y + other.1 as i32,
            w: self.w,
            h: self.h,
        }
    }
}
