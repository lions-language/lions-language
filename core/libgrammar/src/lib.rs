use crate::token::TokenData;

#[macro_use]
extern crate lazy_static;

#[macro_export]
macro_rules! extract_token_data {
    ($td:ident, $typ:ident) => {
        match $td {
            TokenData::$typ(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
}

pub mod lexical;
pub mod grammar;
mod control;
pub mod token;

