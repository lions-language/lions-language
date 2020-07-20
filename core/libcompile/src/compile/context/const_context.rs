use crate::compile::{ConstContext};
use libgrammar::token::{TokenValue, TokenType
        , TokenData};
use libtype::instruction::{AddressKey};

impl ConstContext {
    pub fn from_token_value(token_value: TokenValue, addr: AddressKey) -> Self {
        match token_value.token_type {
            TokenType::Const(t) => {
                match token_value.token_data {
                    Some(v) => {
                        match v {
                            TokenData::Const(d) => {
                                Self {
                                    typ: t,
                                    data: d,
                                    addr: addr
                                }
                            },
                            _ => {
                                panic!("should not happend");
                            }
                        }
                    },
                    None => {
                        panic!("shoudle not happend");
                    }
                }
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
}
