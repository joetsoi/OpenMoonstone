use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};
use warmy;

use loadable_macro_derive::{LoadableRon, LoadableYaml};

type DamageTable = HashMap<String, u32>;

#[derive(Debug, Clone, Serialize, Deserialize, LoadableYaml, LoadableRon)]
#[serde(transparent)]
pub struct DamageTables(pub HashMap<String, DamageTable>);
