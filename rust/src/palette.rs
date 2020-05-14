use std::collections::HashMap;

use ggez::{filesystem, Context};
use serde_derive::{Deserialize, Serialize};
use serde_yaml::Value;
use warmy;

use loadable_macro_derive::{LoadableRon, LoadableYaml};

use crate::error::LoadError;
use crate::manager::GameYaml;

#[derive(Debug, Clone, Serialize, Deserialize, LoadableYaml, LoadableRon)]
#[serde(transparent)]
pub struct PaletteSwaps(pub HashMap<String, Vec<u16>>);
