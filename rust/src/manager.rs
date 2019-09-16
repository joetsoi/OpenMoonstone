use std::error::Error;
use std::fmt;
use std::path::Path;

use failure;
use failure::err_msg;
use failure_derive::Fail;
use ggez;
use ggez::{filesystem, Context};
use serde_yaml::Value;
use warmy::{Load, Loaded, SimpleKey, Storage};

use crate::error::{err_from, BaseLoadError, CompatError, LoadError};
use crate::files::collide::{parse_collide_hit, CollisionBoxes};
use crate::files::TerrainFile;
use crate::objects::{ObjectsFile, TextureAtlas};
use crate::piv::PivImage;

#[derive(Debug, Fail)]
#[fail(display = "Failed to read game data: {}", message)]

struct GameDataError {
    message: String,
}


#[derive(Debug, Clone)]
pub struct GameYaml {
    resource_name: String,
    pub yaml: Value,
}

impl fmt::Display for GameYaml {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "GameYaml for {}", self.resource_name)
    }
}

impl Load<Context, SimpleKey> for GameYaml {
    //type Key = warmy::LogicalKey;
    // type Error = CompatError;
    // type Error = Box<dyn Error>;
    type Error = BaseLoadError;

    fn load(
        key: SimpleKey,
        store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        match key {
            warmy::SimpleKey::Logical(key) => {
                let file = filesystem::open(ctx, &key)?;
                //let file = filesystem::open(ctx, key).map_err(err_from)?;
                Ok(Loaded::from(GameYaml {
                    resource_name: key.clone(),
                    yaml: serde_yaml::from_reader(file)?,
                    //yaml: serde_yaml::from_reader(file).map_err(err_from)?,
                }))
            }
            // warmy::SimpleKey::Path(_) => return Err(err_msg("error").compat()),
            warmy::SimpleKey::Path(_) => return Err(BaseLoadError::PathLoadNotImplemented),
        }
    }
}

impl Load<Context, SimpleKey> for PivImage {
    // type Key = LogicalKey;
    // type Error = CompatError;
    type Error = LoadError<GameYaml>;

    fn load(
        key: SimpleKey,
        store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        let yaml = store
            .get::<GameYaml>(&SimpleKey::from("/files.yaml"), ctx)?;
        let scenes = &yaml.borrow().yaml["scenes"];
        match &key {
            warmy::SimpleKey::Logical(key) => {
                let mut file = filesystem::open(
                    ctx,
                    // todo: remove expect
                    Path::new("/moonstone/").join(
                        &scenes[key]
                            .as_str()
                            // .unwrap_or_else(|| panic!("yaml error for {}", key)),
                            .ok_or_else(|| LoadError::YamlKeyDoesNotExist { key: key.clone() })?
                    ),
                )?;
                // )
                // .map_err(err_from)?;

                Ok(Loaded::from(
                    // PivImage::from_reader(&mut file).map_err(err_from)?,
                    PivImage::from_reader(&mut file)?,
                ))
            }
            warmy::SimpleKey::Path(_) => return Err(LoadError::PathLoadNotImplemented),
        }
    }
}

impl Load<Context, SimpleKey> for TextureAtlas {
    // type Key = LogicalKey;
    // type Error = CompatError;
    type Error = LoadError<GameYaml>;
    // type Error = Box<dyn Error>;
    fn load(
        key: SimpleKey,
        store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        let yaml = store
            .get::<GameYaml>(&SimpleKey::from("/files.yaml"), ctx)?;
            // TODO: warmy::StoreErrorOr does not implement Error
            // .expect("store error loading TextureAtlas");
        match &key {
            warmy::SimpleKey::Logical(key) => {
                let object = &yaml.borrow().yaml["objects"][key];
                let mut file = filesystem::open(
                    ctx,
                    Path::new("/moonstone/").join(&object["file"].as_str().expect("yaml error")),
                // ).map_err(err_from)?;
                )?;

                let objects = ObjectsFile::from_reader(&mut file)?;
                let texture_size = object["texture_size"].as_u64().unwrap() as u32;

                // let objects = ObjectsFile::from_reader(&mut file).map_err(err_from)?;
                // let texture_size = object["texture_size"].as_u64().unwrap() as u32;

                objects
                    .to_texture_atlas(texture_size as i32)
                    .map(Loaded::from)
                    .map_err(|e| e.into())
                    // .map_err(|e| {
                    //     failure::Error::from(GameDataError {
                    //         message: format!("Failed loading {}. {} in files.yaml", key, e),
                    //     })
                    //     .compat()
                    // })
            }
            warmy::SimpleKey::Path(_) => return Err(LoadError::PathLoadNotImplemented),
            // warmy::SimpleKey::Path(_) => return Err(err_msg("error").compat()),
            // warmy::SimpleKey::Path(_) => return Err(Box::new(LoadError::PathLoadNotImplemented)),
        }
    }
}

impl Load<Context, SimpleKey> for CollisionBoxes {
    // type Key = LogicalKey;
    type Error = LoadError<GameYaml>;
    fn load(
        key: SimpleKey,
        store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        let yaml = store
            .get::<GameYaml>(&SimpleKey::from("/files.yaml"), ctx)?;
        match &key {
            warmy::SimpleKey::Logical(key) => {
                let object = &yaml.borrow().yaml[key];
                let mut file = filesystem::open(
                    ctx,
                    Path::new("/moonstone/").join(object.as_str().expect("yaml error")),
                )?;
                parse_collide_hit(&mut file).map(Loaded::from).map_err(|e| e.into())
                // parse_collide_hit(&mut file).map(Loaded::from).map_err(|e| {
                //     failure::Error::from(GameDataError {
                //         message: format!("Failed loading {}. {} in files.yaml", key.as_str(), e),
                //     })
                //     .compat()
                // })
            }
            // warmy::SimpleKey::Path(_) => return Err(err_msg("error").compat()),
            warmy::SimpleKey::Path(_) => return Err(LoadError::PathLoadNotImplemented),
        }
    }
}

impl Load<Context, SimpleKey> for TerrainFile {
    // type Key = LogicalKey;
    type Error = CompatError;
    fn load(
        key: SimpleKey,
        store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        let yaml = store
            .get::<GameYaml>(&SimpleKey::from("/files.yaml"), ctx)
            // TODO: warmy::StoreErrorOr does not implement Error
            .expect("store error loading TerrainFile");
        match key {
            warmy::SimpleKey::Logical(key) => {
                let terrain = &yaml.borrow().yaml["terrain"][key.as_str()];
                let mut file = filesystem::open(
                    ctx,
                    Path::new("/moonstone/").join(&terrain.as_str().expect("invalid yaml error")),
                )
                .map_err(err_from)?;

                TerrainFile::from_reader(&mut file)
                    .map(Loaded::from)
                    .map_err(err_from)
            }
            warmy::SimpleKey::Path(_) => return Err(err_msg("error").compat()),
        }
        // let objects = ObjectsFile::from_reader(&mut file).map_err(err_from)?;
        // let texture_size = object["texture_size"].as_u64().unwrap() as u32;

        // objects
        //     .to_texture_atlas(texture_size as i32)
        //     .map(Loaded::from)
        //     .map_err(|e| {
        //         failure::Error::from(GameDataError {
        //             message: format!("Failed loading {}. {} in files.yaml", key.as_str(), e),
        //         })
        //         .compat()
        //     })
    }
}
