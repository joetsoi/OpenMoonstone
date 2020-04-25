use std::collections::HashMap;

use ggez::{filesystem, Context};
use serde_derive::{Deserialize, Serialize};
use serde_yaml::Value;
use warmy;

use loadable_yaml_macro_derive::LoadableYaml;
use crate::error::{err_from, CompatError};
use crate::error::LoadError;
use crate::manager::GameYaml;
use failure::err_msg;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sprite {
    pub animations: HashMap<String, Animation>,
}

impl warmy::Load<Context, warmy::SimpleKey> for Sprite {
    // type Key = warmy::LogicalKey;
    // type Error = CompatError;
    type Error = LoadError<GameYaml>;

    fn load(
        key: warmy::SimpleKey,
        _store: &mut warmy::Storage<ggez::Context, warmy::SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self, warmy::SimpleKey>, Self::Error> {
        match key {
            warmy::SimpleKey::Logical(key) => {
                let file = filesystem::open(ctx, key)?;
                let yaml: Value = serde_yaml::from_reader(file)?;

                Ok(warmy::Loaded::from(Sprite {
                    animations: serde_yaml::from_value(yaml)?,
                }))
            }
            // warmy::SimpleKey::Path(_) => return Err(err_msg("error").compat()),
            warmy::SimpleKey::Path(_) => return Err(LoadError::PathLoadNotImplemented),
        }
        // Ok(Sprite {
        //     animations: serde_yaml::from_value(yaml).map_err(err_from)?,
        // })
    }
}
