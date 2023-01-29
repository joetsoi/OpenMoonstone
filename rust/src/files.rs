use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod collide;
pub mod terrain;

pub use self::terrain::{Background, TerrainFile};

#[derive(Debug, Serialize, Deserialize)]
pub struct Files {
    pub scenes: HashMap<String, String>,
    pub terrain: HashMap<String, Terrain>,
    pub objects: HashMap<String, TextureAtlasFile>,
    pub collide: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Terrain {
    pub file: String,
    pub terrain: Background,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TextureAtlasFile {
    file: String,
    texture_size: i32,
}
