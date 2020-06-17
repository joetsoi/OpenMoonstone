use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};

use loadable_macro_derive::LoadableRon;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub i: i32,
    pub j: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepDistance {
    pub x_axis: Vec<Vec<Vector>>,
    pub y_axis: Vec<Vec<Vector>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, LoadableRon)]
#[serde(transparent)]
pub struct MoveDistances {
    pub distances: HashMap<String, StepDistance>,
}
