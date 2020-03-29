use std::error::Error;
use std::fmt;

use failure::{self, Fail};
use ggez::Context;
use ron;
use warmy;
use warmy::{Load, SimpleKey, StoreErrorOr};

use crate::campaign::movement_cost::CampaignMap;
use crate::files::collide::CollideHitParseError;
use crate::manager::GameYaml;
use crate::objects::TextureSizeTooSmall;
use crate::piv::PivImage;
use crate::ron::{FromRon, GameRon};
use crate::scenes::map::MapData;

#[derive(Debug)]
pub enum MoonstoneError {
    Map(StoreErrorOr<MapData, Context, SimpleKey>),
    Piv(StoreErrorOr<PivImage, Context, SimpleKey>),
    // CampaignMap(StoreErrorOr<CampaignMap, Context, SimpleKey>),
    Ron(StoreErrorOr<GameRon<CampaignMap>, Context, SimpleKey, FromRon>),
    Ggez(ggez::error::GameError),
}

impl Error for MoonstoneError {}

impl fmt::Display for MoonstoneError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MoonstoneError::Map(ref err) => err.fmt(f),
            MoonstoneError::Piv(ref err) => err.fmt(f),
            // MoonstoneError::CampaignMap(ref err) => err.fmt(f),
            MoonstoneError::Ggez(ref err) => err.fmt(f),
            MoonstoneError::Ron(ref err) => err.fmt(f),
        }
    }
}

impl From<StoreErrorOr<MapData, Context, SimpleKey>> for MoonstoneError {
    fn from(err: StoreErrorOr<MapData, Context, SimpleKey>) -> MoonstoneError {
        MoonstoneError::Map(err)
    }
}

impl From<StoreErrorOr<GameRon<CampaignMap>, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(
        err: StoreErrorOr<GameRon<CampaignMap>, Context, SimpleKey, FromRon>,
    ) -> MoonstoneError {
        MoonstoneError::Ron(err)
    }
}

impl From<StoreErrorOr<PivImage, Context, SimpleKey>> for MoonstoneError {
    fn from(err: StoreErrorOr<PivImage, Context, SimpleKey>) -> MoonstoneError {
        MoonstoneError::Piv(err)
    }
}

// impl From<StoreErrorOr<CampaignMap, Context, SimpleKey>> for MoonstoneError {
//     fn from(err: StoreErrorOr<CampaignMap, Context, SimpleKey>) -> MoonstoneError {
//         MoonstoneError::CampaignMap(err)
//     }
// }

impl From<ggez::error::GameError> for MoonstoneError {
    fn from(err: ggez::error::GameError) -> MoonstoneError {
        MoonstoneError::Ggez(err)
    }
}
pub type CompatError = failure::Compat<failure::Error>;

pub fn err_from<F: Fail>(f: F) -> CompatError {
    failure::Error::from(f).compat()
}

#[derive(Debug)]
pub enum BaseLoadError {
    Io(std::io::Error),
    Ggez(ggez::error::GameError),
    Serde(serde_yaml::Error),
    RonDeserialize(ron::de::Error),
    PathLoadNotImplemented,
}

impl Error for BaseLoadError {}

impl fmt::Display for BaseLoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BaseLoadError::Io(ref err) => err.fmt(f),
            BaseLoadError::Ggez(ref err) => err.fmt(f),
            BaseLoadError::Serde(ref err) => err.fmt(f),
            BaseLoadError::PathLoadNotImplemented => write!(f, "Path not implemented"),
            BaseLoadError::RonDeserialize(ref err) => err.fmt(f),
        }
    }
}

impl From<ggez::error::GameError> for BaseLoadError {
    fn from(err: ggez::error::GameError) -> BaseLoadError {
        BaseLoadError::Ggez(err)
    }
}

impl From<serde_yaml::Error> for BaseLoadError {
    fn from(err: serde_yaml::Error) -> BaseLoadError {
        BaseLoadError::Serde(err)
    }
}

impl From<std::io::Error> for BaseLoadError {
    fn from(err: std::io::Error) -> BaseLoadError {
        BaseLoadError::Io(err)
    }
}

impl From<ron::de::Error> for BaseLoadError {
    fn from(err: ron::de::Error) -> BaseLoadError {
        BaseLoadError::RonDeserialize(err)
    }
}

#[derive(Debug)]
pub enum LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    Io(std::io::Error),
    Ggez(ggez::error::GameError),
    Serde(serde_yaml::Error),
    Warmy(warmy::load::StoreErrorOr<T, Context, SimpleKey>),
    PathLoadNotImplemented,
    YamlKeyDoesNotExist { key: String },
    TextureSizeTooSmall(TextureSizeTooSmall),
    CollideHit(CollideHitParseError),
}

impl<T> fmt::Display for LoadError<T>
where
    T: Load<Context, SimpleKey> + fmt::Display,
    T::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LoadError::Io(ref err) => err.fmt(f),
            LoadError::Ggez(ref err) => err.fmt(f),
            LoadError::Serde(ref err) => err.fmt(f),
            LoadError::Warmy(ref err) => err.fmt(f),
            LoadError::PathLoadNotImplemented => write!(f, "Path not implemented"),
            LoadError::YamlKeyDoesNotExist { ref key } => {
                write!(f, "Yaml key {} does not exist", key)
            }
            LoadError::TextureSizeTooSmall(ref err) => err.fmt(f),
            LoadError::CollideHit(ref err) => err.fmt(f),
        }
    }
}

impl<T> Error for LoadError<T>
where
    T: Load<Context, SimpleKey> + fmt::Display + fmt::Debug,
    T::Error: fmt::Debug,
{
}

impl<T> From<ggez::error::GameError> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: ggez::error::GameError) -> LoadError<T> {
        LoadError::Ggez(err)
        // LoadError::Ggez { source: err }
    }
}

// impl From<serde_yaml::Error> for LoadError
impl<T> From<serde_yaml::Error> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: serde_yaml::Error) -> LoadError<T> {
        // LoadError::Serde { source: err }
        LoadError::Serde(err)
    }
}

impl<T> From<std::io::Error> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: std::io::Error) -> LoadError<T> {
        // LoadError::Io { source: err }
        LoadError::Io(err)
    }
}

impl<T> From<TextureSizeTooSmall> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: TextureSizeTooSmall) -> LoadError<T> {
        LoadError::TextureSizeTooSmall(err)
    }
}

impl<T> From<CollideHitParseError> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: CollideHitParseError) -> LoadError<T> {
        LoadError::CollideHit(err)
    }
}

// impl From<warmy::load::StoreErrorOr<GameYaml, Context, SimpleKey>> for LoadError
impl<T> From<warmy::load::StoreErrorOr<T, Context, SimpleKey>> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: warmy::load::StoreErrorOr<T, Context, SimpleKey>) -> LoadError<T> {
        LoadError::Warmy(err)
    }
}
