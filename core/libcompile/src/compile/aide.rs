use libgrammar::token::{TokenValue, TokenType};
use libtype::{Type, Primeval};
use super::{Compiler, Compile, ConstContext};

impl<F: Compile> Compiler<F> {
    pub fn tokentype_to_type(&self, typ: TokenType) -> Type {
        match typ {
            TokenType::Const(pt) => {
                Type::Primeval(Primeval::new(pt))
            },
            _ => {
                unimplemented!();
            }
        }
    }
}
