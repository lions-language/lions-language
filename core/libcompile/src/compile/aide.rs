use libgrammar::token::{TokenType, TokenValue, TokenData};
use libtype::{Type, Data, TypeValue
    , Primeval, TypeAttrubute
    , DataValue};
use super::{Compiler, Compile, TokenValueExpand
    , CallFunctionContext};

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

    pub fn call_function_and_ctrl_scope(&mut self, context: CallFunctionContext) {
        // self.scope_context.enter();
        self.cb.enter_scope();
        self.cb.call_function(context);
        // self.scope_context.leave();
        self.cb.leave_scope();
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
