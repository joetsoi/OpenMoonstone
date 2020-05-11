use std::collections::HashMap;

use ggez::{filesystem, Context};
use serde_yaml::Value;
use warmy;

use crate::error::LoadError;
use crate::manager::GameYaml;

#[derive(Debug, Clone)]
pub struct PaletteSwaps(pub HashMap<String, Vec<u16>>);

// TODO: change this to a macro along with DamageTables
impl warmy::Load<Context, warmy::SimpleKey> for PaletteSwaps {
    type Error = LoadError<GameYaml>;

    fn load(
        key: warmy::SimpleKey,
        _store: &mut warmy::Storage<ggez::Context, warmy::SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self, warmy::SimpleKey>, Self::Error> {
        match key {
            warmy::SimpleKey::Logical(key) => {
                let file = filesystem::open(ctx, key.as_str())?;
                let yaml: Value = serde_yaml::from_reader(file)?;

                Ok(warmy::Loaded::from(PaletteSwaps(serde_yaml::from_value(
                    yaml,
                )?)))
            }
            warmy::SimpleKey::Path(_) => return Err(LoadError::PathLoadNotImplemented),
        }
    }
}
