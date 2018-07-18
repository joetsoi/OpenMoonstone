use ggez::{Context, GameError};
use serde_yaml::Value;
use warmy;

use crate::error::{err_from, CompatError};

pub enum ImageType {
    NonSolid,
    Collidee,
}

pub struct Frame {
    sheet: String,
    image: u32,
    x: u32,
    y: u32,
    image_type: ImageType,
}

pub struct Animation {
    frames: Vec<Frame>
}

impl warmy::Load<Context> for Animation {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;
        Ok(warmy::Loaded::from(Animation{frames: Vec::new()}))
    }

}

// impl Frame {
//     pub fn from_yaml(yaml: &Value) -> Frame{
//     }
// }
