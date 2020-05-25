use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};
use warmy;

use loadable_macro_derive::{LoadableRon, LoadableYaml};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SpriteData {
    pub sprites: HashMap<String, Sprite>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ImageType {
    NonSolid,
    Collidee,
    Collider,
    Blood,
    BloodStain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    pub sheet: String,
    pub image: usize,
    pub x: i32,
    pub y: i32,
    pub image_type: ImageType,
}

impl Image {
    pub fn is_collidee(&self) -> bool {
        self.image_type == ImageType::Collidee
    }

    pub fn is_collider(&self) -> bool {
        self.image_type == ImageType::Collider
    }

    pub fn is_blood(&self) -> bool {
        match self.image_type {
            ImageType::Blood | ImageType::BloodStain => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Frame {
    pub images: Vec<Image>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Animation {
    pub frames: Vec<Frame>,
    #[serde(default)]
    pub order: Option<Vec<i32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, LoadableRon, LoadableYaml)]
#[serde(transparent)]
pub struct Sprite {
    pub animations: HashMap<String, Animation>,
}
