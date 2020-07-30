use libgrammar::token::{TokenType, TokenValue, TokenData};
use libtype::{Type, Data, TypeValue
    , Primeval, TypeAttrubute
    , DataValue};
use super::{Compiler, Compile, TokenValueExpand};

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

impl TokenValueExpand for TokenValue {
    fn to_type(&self) -> Type {
        match self.token_type_clone() {
            TokenType::Const(t) => {
                Type::new(TypeValue::Primeval(Primeval::new(
                            t)), TypeAttrubute::Ref)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn to_data(self) -> Data {
        match self.token_data {
            Some(data) => {
                match data {
                    TokenData::Const(d) => {
                        Data::new(DataValue::Primeval(d))
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            },
            None => {
                Data::new_empty()
            }
        }
    }
}
