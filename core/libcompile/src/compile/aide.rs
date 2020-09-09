use libstructtype::structure::{StructControl};
use libgrammar::token::{TokenType, TokenValue, TokenData};
use libcommon::ptr::{RefPtr};
use libgrammar::grammar::TypeToken;
use libtype::{Type, Data, TypeValue
    , Primeval, TypeAttrubute
    , DataValue, AddressValue
    , TypeAddrType, Structure
    , StructObject};
use super::{Compiler, Compile, TokenValueExpand
    , CallFunctionContext, AddressValueExpand
    , TypeTokenExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn to_type(&self, typ: TypeToken) -> Type {
        typ.to_type::<F>(RefPtr::from_ref(self))
    }

    pub fn call_function_and_ctrl_scope(&mut self, context: CallFunctionContext) {
        // self.scope_context.enter();
        self.cb_enter_scope();
        self.cb.call_function(context);
        // self.scope_context.leave();
        self.cb_leave_scope();
    }

    pub fn cb_enter_scope(&mut self) {
        self.cb.enter_scope();
    }

    pub fn cb_leave_scope(&mut self) {
        self.cb.leave_scope();
    }
}

impl TokenValueExpand for TokenValue {
    fn to_type(&self) -> Type {
        match self.token_type_clone() {
            TokenType::Const(t) => {
                Type::new(TypeValue::Primeval(Primeval::new(
                            t)), TypeAttrubute::Ref/*TODO*/)
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

impl AddressValueExpand for AddressValue {
    fn add_scope(&mut self, n: usize) {
        /*
         * 对 address key 中的 scope 加值
         * */
        let addr = self.addr_mut();
        *addr.scope_mut() += n;
    }

    fn clone_with_index_plus(&self, n: usize) -> AddressValue {
        let mut value = self.clone();
        *value.addr_mut().index_mut() += n as u64;
        value
    }

    fn clone_with_scope_plus(&self, n: usize) -> AddressValue {
        let mut value = self.clone();
        *value.addr_mut().scope_mut() += n;
        value
    }

    fn clone_with_scope_minus(&self, n: usize) -> AddressValue {
        let mut value = self.clone();
        *value.addr_mut().scope_mut() -= n;
        value
    }

    fn addr_with_scope_minus(mut self, n: usize) -> AddressValue {
        *self.addr_mut().scope_mut() -= n;
        self
    }

    fn addr_with_scope_plus(mut self, n: usize) -> AddressValue {
        *self.addr_mut().scope_mut() += n;
        self
    }

    fn addr_mut_with_scope_minus(&mut self, n: usize) {
        *self.addr_mut().scope_mut() -= n;
    }

    fn addr_mut_with_scope_plus(&mut self, n: usize) {
        *self.addr_mut().scope_mut() += n;
    }
}

impl TypeTokenExpand for TypeToken {
    fn to_type<F: Compile>(self, cp: RefPtr) -> Type {
        match self {
            TypeToken::Single(tv) => {
                let token_data = tv.token_data().expect("should not happend");
                let t = extract_token_data!(token_data, Id);
                match Type::from_str(&t) {
                    Some(typ) => {
                        typ
                    },
                    None => {
                        let compiler = cp.as_ref::<Compiler<F>>();
                        match compiler.struct_control.find_define(
                            compiler.module_stack.current().name_ref()
                            , &t) {
                            Some(sd) => {
                                // println!("--- {:?}, {:?}", sd, StructObject::from_ref(sd));
                                // println!("name: {}", t);
                                // sd.member_ref().as_ref().unwrap().print_members();
                                let struct_obj = StructObject::from_ref(sd);
                                /*
                                println!("xxxxxxxxxxxxx {:?}", struct_obj);
                                struct_obj.as_ref().name_ref();
                                */
                                Type::new_with_addrtyp(
                                    TypeValue::Structure(Structure::new(struct_obj))
                                    , TypeAddrType::Stack)
                            },
                            None => {
                                unimplemented!("unknow type: {:?}", t);
                            }
                        }
                    }
                }
            },
            _ => {
                unimplemented!();
            }
        }
    }
}
