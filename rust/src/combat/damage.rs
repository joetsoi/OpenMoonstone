use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};
// use warmy;

// use loadable_macro_derive::LoadableRon;

type DamageTable = HashMap<String, u32>;

// #[derive(Debug, Clone, Serialize, Deserialize, LoadableRon)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DamageTables(pub HashMap<String, DamageTable>);
