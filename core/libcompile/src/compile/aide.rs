use libgrammar::token::{TokenType, TokenValue};
use libtype::{Type, TypeValue, Primeval, TypeAttrubute};
use super::{Compiler, Compile};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn tokentype_to_type(&self, typ: TokenType) -> Type {
        match typ {
            TokenType::Const(pt) => {
                Type::new(TypeValue::Primeval(Primeval::new(
                        pt)), TypeAttrubute::Ref)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    pub fn consttoken_to_type(&self, value: &TokenValue) -> Type {
        match value.token_type_clone() {
            TokenType::Const(t) => {
                Type::new(TypeValue::Primeval(Primeval::new(
                            t)), TypeAttrubute::Ref)
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
}
