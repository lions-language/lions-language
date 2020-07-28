use libgrammar::token::{TokenType};
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
}
