use std::error::Error;
use std::fmt;

use ggez::Context;
use ron;
use warmy;
use warmy::{Load, SimpleKey, StoreErrorOr};

use crate::animation::{Sprite, SpriteData};
use crate::campaign::movement_cost::CampaignMap;
use crate::files::collide::CollideHitParseError;
use crate::objects::{TextureAtlas, TextureSizeTooSmall};
use crate::piv::PivImage;
use crate::ron::{Files, FromDosFilesRon, FromRon, GameRon};
use crate::scenes::map::{FileList, Locations, MapData};
use crate::text::Screen;

#[derive(Debug)]
pub enum MoonstoneError {
    ColourSwapFailed(String),
    Io(std::io::Error),
    Map(StoreErrorOr<MapData, Context, SimpleKey>),
    Piv(StoreErrorOr<PivImage, Context, SimpleKey>),
    Sprite(StoreErrorOr<Sprite, Context, SimpleKey>),
    TextureAtlas(StoreErrorOr<TextureAtlas, Context, SimpleKey>),
    TextureSizeTooSmall(TextureSizeTooSmall),
    Ron(StoreErrorOr<GameRon<CampaignMap>, Context, SimpleKey, FromRon>),
    FileList(StoreErrorOr<GameRon<FileList>, Context, SimpleKey, FromRon>),
    Locations(StoreErrorOr<GameRon<Locations>, Context, SimpleKey, FromRon>),
    ScreenRon(StoreErrorOr<Screen, Context, SimpleKey, FromRon>),
    SpriteRon(StoreErrorOr<GameRon<Sprite>, Context, SimpleKey, FromRon>),
    SpriteData(StoreErrorOr<GameRon<SpriteData>, Context, SimpleKey, FromRon>),
    FilesRon(StoreErrorOr<GameRon<Files>, Context, SimpleKey, FromRon>),
    Ggez(ggez::error::GameError),
    PathLoadNotImplemented,
    NotInDosFiles,
}

impl Error for MoonstoneError {}

impl fmt::Display for MoonstoneError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MoonstoneError::ColourSwapFailed(ref err) => err.fmt(f),
            MoonstoneError::Io(ref err) => err.fmt(f),
            MoonstoneError::Map(ref err) => err.fmt(f),
            MoonstoneError::Piv(ref err) => err.fmt(f),
            MoonstoneError::Sprite(ref err) => err.fmt(f),
            MoonstoneError::TextureAtlas(ref err) => err.fmt(f),
            MoonstoneError::TextureSizeTooSmall(ref err) => err.fmt(f),
            MoonstoneError::Ron(ref err) => err.fmt(f),
            MoonstoneError::FileList(ref err) => err.fmt(f),
            MoonstoneError::Locations(ref err) => err.fmt(f),
            MoonstoneError::ScreenRon(ref err) => err.fmt(f),
            MoonstoneError::SpriteRon(ref err) => err.fmt(f),
            MoonstoneError::SpriteData(ref err) => err.fmt(f),
            MoonstoneError::FilesRon(ref err) => err.fmt(f),
            MoonstoneError::Ggez(ref err) => err.fmt(f),
            MoonstoneError::PathLoadNotImplemented => write!(f, "Path not implemented"),
            MoonstoneError::NotInDosFiles => write!(f, "File not found in dos_files.ron"),
        }
    }
}

impl From<std::io::Error> for MoonstoneError {
    fn from(err: std::io::Error) -> MoonstoneError {
        MoonstoneError::Io(err)
    }
}

impl From<TextureSizeTooSmall> for MoonstoneError {
    fn from(err: TextureSizeTooSmall) -> MoonstoneError {
        MoonstoneError::TextureSizeTooSmall(err)
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

impl From<StoreErrorOr<GameRon<FileList>, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(err: StoreErrorOr<GameRon<FileList>, Context, SimpleKey, FromRon>) -> MoonstoneError {
        MoonstoneError::FileList(err)
    }
}

impl From<StoreErrorOr<GameRon<Locations>, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(err: StoreErrorOr<GameRon<Locations>, Context, SimpleKey, FromRon>) -> MoonstoneError {
        MoonstoneError::Locations(err)
    }
}

impl From<StoreErrorOr<Screen, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(err: StoreErrorOr<Screen, Context, SimpleKey, FromRon>) -> MoonstoneError {
        MoonstoneError::ScreenRon(err)
    }
}

impl From<StoreErrorOr<GameRon<Sprite>, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(err: StoreErrorOr<GameRon<Sprite>, Context, SimpleKey, FromRon>) -> MoonstoneError {
        MoonstoneError::SpriteRon(err)
    }
}

impl From<StoreErrorOr<GameRon<SpriteData>, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(err: StoreErrorOr<GameRon<SpriteData>, Context, SimpleKey, FromRon>) -> MoonstoneError {
        MoonstoneError::SpriteData(err)
    }
}

impl From<StoreErrorOr<GameRon<Files>, Context, SimpleKey, FromRon>> for MoonstoneError {
    fn from(err: StoreErrorOr<GameRon<Files>, Context, SimpleKey, FromRon>) -> MoonstoneError {
        MoonstoneError::FilesRon(err)
    }
}

impl From<StoreErrorOr<PivImage, Context, SimpleKey>> for MoonstoneError {
    fn from(err: StoreErrorOr<PivImage, Context, SimpleKey>) -> MoonstoneError {
        MoonstoneError::Piv(err)
    }
}

impl From<StoreErrorOr<Sprite, Context, SimpleKey>> for MoonstoneError {
    fn from(err: StoreErrorOr<Sprite, Context, SimpleKey>) -> MoonstoneError {
        MoonstoneError::Sprite(err)
    }
}

impl From<StoreErrorOr<TextureAtlas, Context, SimpleKey>> for MoonstoneError {
    fn from(err: StoreErrorOr<TextureAtlas, Context, SimpleKey>) -> MoonstoneError {
        MoonstoneError::TextureAtlas(err)
    }
}

impl From<ggez::error::GameError> for MoonstoneError {
    fn from(err: ggez::error::GameError) -> MoonstoneError {
        MoonstoneError::Ggez(err)
    }
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
pub enum RonLoadError<T>
where
    T: Load<Context, SimpleKey, FromRon>,
    T::Error: fmt::Debug,
{
    CollideHit(CollideHitParseError),
    Ggez(ggez::error::GameError),
    PathLoadNotImplemented,
    Warmy(warmy::load::StoreErrorOr<T, Context, SimpleKey, FromRon>),
}

impl<T> fmt::Display for RonLoadError<T>
where
    T: Load<Context, SimpleKey, FromRon> + fmt::Display,
    T::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RonLoadError::CollideHit(ref err) => err.fmt(f),
            RonLoadError::Ggez(ref err) => err.fmt(f),
            RonLoadError::PathLoadNotImplemented => write!(f, "Path not implemented"),
            RonLoadError::Warmy(ref err) => err.fmt(f),
        }
    }
}

impl<T> Error for RonLoadError<T>
where
    T: Load<Context, SimpleKey, FromRon> + fmt::Display + fmt::Debug,
    T::Error: fmt::Debug,
{
}

impl<T> From<CollideHitParseError> for RonLoadError<T>
where
    T: Load<Context, SimpleKey, FromRon>,
    T::Error: fmt::Debug,
{
    fn from(err: CollideHitParseError) -> RonLoadError<T> {
        RonLoadError::CollideHit(err)
    }
}

impl<T> From<ggez::error::GameError> for RonLoadError<T>
where
    T: Load<Context, SimpleKey, FromRon>,
    T::Error: fmt::Debug,
{
    fn from(err: ggez::error::GameError) -> RonLoadError<T> {
        RonLoadError::Ggez(err)
    }
}

impl<T> From<warmy::load::StoreErrorOr<T, Context, SimpleKey, FromRon>> for RonLoadError<T>
where
    T: Load<Context, SimpleKey, FromRon>,
    T::Error: fmt::Debug,
{
    fn from(err: warmy::load::StoreErrorOr<T, Context, SimpleKey, FromRon>) -> RonLoadError<T> {
        RonLoadError::Warmy(err)
    }
}

// older yaml load error
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
    // WarmyFromDosFilesRon(warmy::load::StoreErrorOr<T, Context, SimpleKey, FromDosFilesRon>),
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
            // LoadError::WarmyFromDosFilesRon(ref err) => err.fmt(f),
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

// impl<T> From<warmy::load::StoreErrorOr<T, Context, SimpleKey, FromDosFilesRon>> for LoadError<T>
// where
//     T: Load<Context, SimpleKey, FromDosFilesRon>,
//     T::Error: fmt::Debug,
// {
//     fn from(err: warmy::load::StoreErrorOr<T, Context, SimpleKey, FromDosFilesRon>) -> LoadError<T> {
//         LoadError::WarmyFromDosFilesRon(err)
//     }
// }
