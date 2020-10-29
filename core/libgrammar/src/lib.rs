use crate::token::TokenData;
use libresult::DescResult;

#[macro_use]
extern crate lazy_static;

#[macro_export]
macro_rules! extract_token_data {
    ($td:expr, $typ:ident) => {
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

#[macro_export]
macro_rules! check_desc_result {
    ($this:expr, $e:expr) => {
        match $e {
            DescResult::Error(e) => {
                $this.panic(&e);
            },
            _ => {}
        }
    };
}

macro_rules! if_true_return {
    ($e:expr) => {
        if $e {
            return;
        }
    }
}

pub mod lexical;
pub mod grammar;
mod control;
pub mod token;
mod module;
