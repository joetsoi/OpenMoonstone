use std::collections::HashMap;

use ggez::{filesystem, Context};
use failure::err_msg;
use serde_yaml::Value;
use warmy;

use crate::error::{err_from, CompatError};

#[derive(Debug, Clone)]
pub struct PaletteSwaps(pub HashMap<String, Vec<u16>>);

// TODO: change this to a macro along with DamageTables
impl warmy::Load<Context, warmy::SimpleKey> for PaletteSwaps {
    // type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: warmy::SimpleKey,
        _store: &mut warmy::Storage<ggez::Context, warmy::SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self, warmy::SimpleKey>, Self::Error> {
        match key {
            warmy::SimpleKey::Logical(key) => {
                let file = filesystem::open(ctx, key.as_str()).map_err(err_from)?;
                let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;

                Ok(warmy::Loaded::from(PaletteSwaps(
                    serde_yaml::from_value(yaml).map_err(err_from)?,
                )))
            }
            warmy::SimpleKey::Path(_) => return Err(err_msg("error").compat()),
        }
    }
}
