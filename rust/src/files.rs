use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use ggez::Context;
use serde::{Deserialize, Serialize};

pub mod collide;
pub mod terrain;

pub use self::terrain::{Background, TerrainFile};

pub fn read(ctx: &mut Context, filename: &str) -> String {
    let mut buffer = String::new();
    let mut file = ctx.fs.open(Path::new(filename)).unwrap();
    file.read_to_string(&mut buffer).unwrap();
    buffer
}

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
