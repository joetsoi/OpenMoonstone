use std::collections::HashMap;
use std::path::Path;

use ggez;
use ggez::{filesystem, Context};
use ron;
use ron::de::from_reader;
use serde::{Deserialize, Serialize};
use warmy::key::SimpleKey;
use warmy::load::{Load, Loaded, Storage};

use crate::error::{BaseLoadError, MoonstoneError};
use crate::files::{terrain::Background, TerrainFile};

// Copied from the warmy ron universal implementation, except loads from
// a ggez filesystem instead.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FromRon;

#[derive(Clone, Debug)]
pub struct GameRon<T>(pub T);

impl<T> Load<Context, SimpleKey, FromRon> for GameRon<T>
where
    T: 'static + for<'de> Deserialize<'de>,
{
    type Error = BaseLoadError;

    fn load(
        key: SimpleKey,
        _store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        match key {
            warmy::SimpleKey::Logical(key) => {
                let file = filesystem::open(ctx, &key)?;
                from_reader(file)
                    .map(|t| GameRon(t))
                    .map(Loaded::without_dep)
                    .map_err(BaseLoadError::RonDeserialize)
            }
            warmy::SimpleKey::Path(_) => return Err(BaseLoadError::PathLoadNotImplemented),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Files {
    terrain: HashMap<String, Terrain>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Terrain {
    file: String,
    terrain: Background,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FromDosFilesRon;

impl Load<Context, SimpleKey, FromDosFilesRon> for TerrainFile {
    type Error = MoonstoneError;

    fn load(
        key: SimpleKey,
        store: &mut Storage<ggez::Context, SimpleKey>,
        ctx: &mut ggez::Context,
    ) -> Result<Loaded<Self, SimpleKey>, Self::Error> {
        let dos_files_ron = store.get_by::<GameRon<Files>, FromRon>(
            &SimpleKey::from("/dos_files.ron"),
            ctx,
            FromRon,
        )?;
        let dos_files = &dos_files_ron.borrow().0;
        match key {
            warmy::SimpleKey::Logical(key) => {
                let entry = dos_files.terrain.get(key.as_str());
                match entry {
                    Some(t) => {
                        let mut file = filesystem::open(
                            ctx,
                            Path::new("/moonstone/").join(t.file.as_str()),
                        )?;
                        Ok(TerrainFile::from_reader(&mut file, t.terrain)
                            .map(Loaded::from)?)
                    }
                    None => Err(MoonstoneError::NotInDosFiles),
                }
            }
            warmy::SimpleKey::Path(_) => return Err(MoonstoneError::PathLoadNotImplemented),
        }
    }
}
