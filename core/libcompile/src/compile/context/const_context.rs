use crate::compile::{ConstContext, TokenValueExpand};
use libgrammar::token::{TokenValue, TokenType};
use libtype::{AddressKey};

impl ConstContext {
    pub fn from_token_value(token_value: TokenValue, addr: AddressKey) -> Self {
        match &token_value.token_type {
            TokenType::Const(_) => {
                Self {
                    typ: token_value.to_const_type().clone(),
                    data: token_value.to_const_data(),
                    addr: addr
                }
            },
            _ => {
                unimplemented!();
            }
        }
    }
}
