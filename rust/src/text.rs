use ggez::Context;
use serde_derive::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::error::{err_from, CompatError};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Screen {
    pub background: String,
    pub text: Vec<Text>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Text {
    string: String,
    font: String,
    bordered: bool,
    centered: bool,
    x: u32,
    y: u32,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Image {
    pub sheet: String,
    pub image: u32,
    pub x: i32,
    pub y: i32,
}

impl warmy::Load<Context> for Screen {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        _store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;
        let screen: Screen = serde_yaml::from_value(yaml).map_err(err_from)?;
        Ok(warmy::Loaded::from(screen))
    }
}
