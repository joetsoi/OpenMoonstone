use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};
use serde_yaml::Value;
use warmy;

use crate::error::{err_from, CompatError};

#[derive(Default, Debug, Clone)]
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
        if self.image_type == ImageType::Collidee {
            true
        } else {
            false
        }
    }

    pub fn is_collider(&self) -> bool {
        if self.image_type == ImageType::Collider {
            true
        } else {
            false
        }
    }

    pub fn is_blood(&self) -> bool {
        match self.image_type {
            ImageType::Blood | ImageType::BloodStain => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub images: Vec<Image>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Animation {
    pub frames: Vec<Frame>,
    #[serde(default)]
    pub order: Option<Vec<i32>>,
}

#[derive(Debug, Clone)]
pub struct Sprite {
    pub animations: HashMap<String, Animation>,
}

impl warmy::Load<Context> for Sprite {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        _store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;

        Ok(warmy::Loaded::from(Sprite {
            animations: serde_yaml::from_value(yaml).map_err(err_from)?,
        }))
    }
}
