use ggez;
use ggez::{filesystem, Context};
use ron;
use ron::de::from_reader;
use serde::Deserialize;
use warmy::key::SimpleKey;
use warmy::load::{Load, Loaded, Storage};

use crate::error::BaseLoadError;

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
        store: &mut Storage<ggez::Context, SimpleKey>,
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
