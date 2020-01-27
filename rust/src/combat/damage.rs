use std::collections::HashMap;

use ggez::{filesystem, Context};
use serde_yaml::Value;
use warmy;

use crate::error::LoadError;
use crate::manager::GameYaml;

type DamageTable = HashMap<String, u32>;

#[derive(Debug, Clone)]
pub struct DamageTables(pub HashMap<String, DamageTable>);

impl warmy::Load<Context, warmy::SimpleKey> for DamageTables {
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

                Ok(warmy::Loaded::from(DamageTables(serde_yaml::from_value(
                    yaml,
                )?)))
            }
            warmy::SimpleKey::Path(_) => return Err(LoadError::PathLoadNotImplemented),
        }
    }
}
