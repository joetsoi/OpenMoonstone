use std::collections::HashMap;

use ggez::{filesystem, Context};
use serde_yaml::Value;
use serde_derive::{Deserialize, Serialize};
use warmy;

use loadable_macro_derive::{LoadableRon, LoadableYaml};

use crate::error::LoadError;
use crate::manager::GameYaml;

type DamageTable = HashMap<String, u32>;

#[derive(Debug, Clone, Serialize, Deserialize, LoadableYaml, LoadableRon)]
#[serde(transparent)]
pub struct DamageTables(pub HashMap<String, DamageTable>);
