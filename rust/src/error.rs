use std::error::Error;
use std::fmt;

use failure::{self, Fail};
use ggez::Context;
use snafu::{ResultExt, Snafu};
use warmy;
use warmy::{Load, SimpleKey};

pub type CompatError = failure::Compat<failure::Error>;

pub fn err_from<F: Fail>(f: F) -> CompatError {
    failure::Error::from(f).compat()
}

#[derive(Debug, Snafu)]
pub enum LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    Io {
        source: std::io::Error,
    },
    Ggez {
        source: ggez::error::GameError,
    },
    #[snafu(display("Serde yaml error: {}", source))]
    Serde {
        source: serde_yaml::Error,
    },
    Warmy {
        store_err: warmy::load::StoreErrorOr<T, Context, SimpleKey>,
    },
    PathLoadNotImplemented,
    #[snafu(display("Yaml key: {} does not exist", key))]
    YamlKeyDoesNotExist { key: String },
}

// impl<T> fmt::Display for LoadError<T>
// where
//     T: Load<Context, SimpleKey> + fmt::Display,
//     T::Error: fmt::Debug,
// {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match *self {
//             LoadError::Io(ref err) => err.fmt(f),
//             LoadError::Ggez(ref err) => err.fmt(f),
//             LoadError::Serde(ref err) => err.fmt(f),
//             LoadError::Warmy(ref err) => err.fmt(f),
//             LoadError::PathLoadNotImplemented => write!(f, "Path not implemented"),
//             LoadError::YamlKeyDoesNotExist => write!(f, "Yaml key does not exist"),
//         }
//     }
// }

// impl<T> Error for LoadError<T>
// where
//     T: Load<Context, SimpleKey> + fmt::Display + fmt::Debug,
//     T::Error: fmt::Debug,
// {
// }

impl<T> From<ggez::error::GameError> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: ggez::error::GameError) -> LoadError<T> {
        // LoadError::Ggez (err)
        LoadError::Ggez { source: err }
    }
}

impl<T> From<serde_yaml::Error> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: serde_yaml::Error) -> LoadError<T> {
        LoadError::Serde { source: err }
    }
}

impl<T> From<std::io::Error> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: std::io::Error) -> LoadError<T> {
        LoadError::Io { source: err }
    }
}

impl<T> From<warmy::load::StoreErrorOr<T, Context, SimpleKey>> for LoadError<T>
where
    T: Load<Context, SimpleKey>,
    T::Error: fmt::Debug,
{
    fn from(err: warmy::load::StoreErrorOr<T, Context, SimpleKey>) -> LoadError<T> {
        LoadError::Warmy { store_err: err }
    }
}
