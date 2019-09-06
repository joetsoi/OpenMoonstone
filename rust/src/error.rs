use std::fmt::Display;
use std::error::Error;
use failure::{self, Fail};
use warmy;

pub type CompatError = failure::Compat<failure::Error>;

pub fn err_from<F: Fail>(f: F) -> CompatError {
    failure::Error::from(f).compat()
}

// #[derive(Debug)]
// pub struct LoadError<T, C, K, M = ()>(warmy::StoreErrorOr<T, C, K, M>) where T: warmy::Load<C, K, M>, K: warmy::Key;

// impl<T: warmy::Load<C, K, M>, C, K: warmy::Key, M> From<warmy::StoreErrorOr<T, C, K, M>> for LoadError<T, C, K, M> {
//     fn from(error: warmy::StoreErrorOr<T, C, K, M>) -> Self {
//         Self(error)
//     }
// }

// impl Error for LoadError<T, C, K, M> {
// }
