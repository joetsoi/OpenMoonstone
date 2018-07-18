use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::io::Error as IoError;
use std::path::Path;

use failure::{self, Fail};
use failure_derive::*;
use ggez::filesystem::Filesystem;
use ggez::{Context, GameError};
use serde_yaml::Error as YamlError;
use serde_yaml::Value;
use warmy;

use crate::objects::{ObjectsFile, TextureAtlas, TextureSizeTooSmall};
use crate::piv::PivImage;

fn err_from<F: Fail>(f: F) -> failure::Compat<failure::Error> {
    failure::Error::from(f).compat()
}

impl warmy::Load<Context> for PivImage {
    type Key = warmy::LogicalKey;
    type Error = failure::Compat<failure::Error>;
    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        // TODO: load file.yaml from the store!
        let file = ctx.filesystem.open("/files.yaml").map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;
        let scenes = &yaml["scenes"];
        let mut file = ctx
            .filesystem
            .open(
                // todo: remove expect
                Path::new("/moonstone/").join(&scenes[key.as_str()].as_str().expect("yaml error")),
            )
            .map_err(err_from)?;

        Ok(warmy::Loaded::from(
            PivImage::from_reader(&mut file).map_err(err_from)?,
        ))
    }
}

impl warmy::Load<Context> for TextureAtlas {
    type Key = warmy::LogicalKey;
    type Error = failure::Compat<failure::Error>;
    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        let file = ctx.filesystem.open("/files.yaml").map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;
        let object = &yaml["objects"][key.as_str()];
        let mut file = ctx
            .filesystem
            .open(Path::new("/moonstone/").join(&object["file"].as_str().expect("yaml error")))
            .map_err(err_from)?;

        let objects = ObjectsFile::from_reader(&mut file).map_err(err_from)?;
        let texture_size = object["texture_size"].as_u64().unwrap() as u32;

        objects
            .to_texture_atlas(texture_size as i32)
            .map(warmy::Loaded::from)
            .map_err(err_from)
    }
}
