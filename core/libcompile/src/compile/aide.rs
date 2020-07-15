use libgrammar::token::{TokenType};
use libtype::{Type, Primeval, TypeAttrubute};
use super::{Compiler, Compile};

impl<F: Compile> Compiler<F> {
    pub fn tokentype_to_type(&self, typ: TokenType) -> Type {
        match typ {
            TokenType::Const(pt) => {
                Type::Primeval(Primeval::new_with_attr(
                        pt, TypeAttrubute::Ref))
            },
            _ => {
                unimplemented!();
            }
        }
    }
}
