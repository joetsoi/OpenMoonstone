use std::collections::HashMap;

use ggez::Context;
use serde_derive::{Deserialize, Serialize};
use warmy;

use loadable_macro_derive::{LoadableRon, LoadableYaml};

#[derive(Debug, Clone, Serialize, Deserialize, LoadableYaml, LoadableRon)]
#[serde(transparent)]
pub struct PaletteSwaps(pub HashMap<String, Vec<u16>>);
