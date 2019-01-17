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
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn intersects(&self, other: &Rect) -> bool {
        self.x < other.x + other.w as i32
            && self.x + other.w as i32 > other.x
            && self.y < other.y + other.h as i32
            && self.h as i32 + self.y > other.y
    }

    pub fn contains_point(self, point: Point) -> bool {
        point.x > self.x
            && point.x < self.x + self.w as i32
            && point.y > self.y
            && point.y < self.y + self.h as i32
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

impl Add<(i32, i32)> for Rect {
    type Output = Rect;

    fn add(self, other: (i32, i32)) -> Rect {
        Rect {
            x: self.x + other.0,
            y: self.y + other.1,
            w: self.w,
            h: self.h,
        }
    }
}

#[derive(Default, Copy, Clone, Debug)]
pub struct Interval {
    pub a: i32,
    pub b: i32,
}

impl Interval {
    pub fn contains_point(self, other: i32) -> bool {
        self.a <= other && self.b >= other
    }
}
