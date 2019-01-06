use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};
use serde_yaml::Value;
use warmy;

use crate::error::{err_from, CompatError};

type DamageTable = HashMap<String, u32>;

#[derive(Debug, Clone)]
pub struct DamageTables(pub HashMap<String, DamageTable>);

impl warmy::Load<Context> for DamageTables {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;

        Ok(warmy::Loaded::from(DamageTables(
            serde_yaml::from_value(yaml).map_err(err_from)?
        )))
    }
}
