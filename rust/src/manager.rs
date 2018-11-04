use std::collections::HashMap;
use std::path::Path;

use failure;
use failure_derive::Fail;
use ggez::Context;
use serde_yaml::Value;
use warmy;

use crate::error::{err_from, CompatError};
use crate::files::collide::{parse_collide_hit, CollisionBoxes};
use crate::objects::{ObjectsFile, TextureAtlas};
use crate::piv::PivImage;

#[derive(Debug, Fail)]
#[fail(display = "Failed to read game data: {}", message)]

struct GameDataError {
    message: String,
}

struct GameYaml {
    pub yaml: Value,
}

impl warmy::Load<Context> for GameYaml {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        Ok(warmy::Loaded::from(GameYaml {
            yaml: serde_yaml::from_reader(file).map_err(err_from)?,
        }))
    }
}

impl warmy::Load<Context> for PivImage {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        let yaml = store
            .get::<_, GameYaml>(&warmy::LogicalKey::new("/files.yaml"), ctx)
            .map_err(err_from)?;
        let scenes = &yaml.borrow().yaml["scenes"];
        let mut file = ctx
            .filesystem
            .open(
                // todo: remove expect
                Path::new("/moonstone/").join(&scenes[key.as_str()].as_str().expect(&format!("yaml error for {}", key.as_str()))),
            ).map_err(err_from)?;

        Ok(warmy::Loaded::from(
            PivImage::from_reader(&mut file).map_err(err_from)?,
        ))
    }
}

impl warmy::Load<Context> for TextureAtlas {
    type Key = warmy::LogicalKey;
    type Error = CompatError;
    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        let yaml = store
            .get::<_, GameYaml>(&warmy::LogicalKey::new("/files.yaml"), ctx)
            .map_err(err_from)?;
        let object = &yaml.borrow().yaml["objects"][key.as_str()];
        let mut file = ctx
            .filesystem
            .open(Path::new("/moonstone/").join(&object["file"].as_str().expect("yaml error")))
            .map_err(err_from)?;

        let objects = ObjectsFile::from_reader(&mut file).map_err(err_from)?;
        let texture_size = object["texture_size"].as_u64().unwrap() as u32;

        objects
            .to_texture_atlas(texture_size as i32)
            .map(warmy::Loaded::from)
            .map_err(|e| {
                failure::Error::from(GameDataError {
                    message: format!("Failed loading {}. {} in files.yaml", key.as_str(), e),
                }).compat()
            })
    }
}

impl warmy::Load<Context> for CollisionBoxes {
    type Key = warmy::LogicalKey;
    type Error = CompatError;
    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        println!("key: {:?}, path: {:?}", key, store.root());
        let yaml = store
            .get::<_, GameYaml>(&warmy::LogicalKey::new("/files.yaml"), ctx)
            .map_err(err_from)?;
        let object = &yaml.borrow().yaml[key.as_str()];
        let mut file = ctx
            .filesystem
            .open(Path::new("/moonstone/").join(object.as_str().expect("yaml error")))
            .map_err(err_from)?;
        parse_collide_hit(&mut file)
            .map(warmy::Loaded::from)
            .map_err(|e| {
                failure::Error::from(GameDataError {
                    message: format!("Failed loading {}. {} in files.yaml", key.as_str(), e),
                }).compat()
            })
    }
}
