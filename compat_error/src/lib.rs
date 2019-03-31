use failure::{self, Fail};

pub type CompatError = failure::Compat<failure::Error>;

pub fn err_from<F: Fail>(f: F) -> CompatError {
    failure::Error::from(f).compat()
}
