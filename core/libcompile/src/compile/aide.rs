use libstructtype::structure::{StructControl};
use libgrammar::token::{TokenType, TokenValue, TokenData};
use libresult::{DescResult};
use libcommon::ptr::{RefPtr};
use libgrammar::grammar::TypeToken;
use libtype::{Type, Data, TypeValue
    , Primeval, TypeAttrubute
    , DataValue, AddressValue
    , AddressKey
    , TypeAddrType, Structure
    , StructObject};
use super::{Compiler, Compile, TokenValueExpand
    , CallFunctionContext, AddressValueExpand
    , TypeTokenExpand, OwnershipMoveContext};
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn to_type(&self, typ: TypeToken) -> Result<Type, DescResult> {
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

    pub fn cb_ownership_move(&mut self, addr: AddressKey
        , src_addr: AddressValue, value_item_context: &ValueBufferItemContext) {
        self.cb.ownership_move(OwnershipMoveContext::new_with_all(
            addr, src_addr.clone()));
        self.scope_context.recycle_address(src_addr.clone());
        /*
         * 如果是移动的变量, 需要将被移动的变量从变量列表中移除
         * */
        match value_item_context {
            ValueBufferItemContext::Variant(v) => {
                let var_name = v.as_ref::<String>();
                // println!("remove {}", var_name);
                self.scope_context.remove_variant_unchecked(
                    src_addr.addr_ref().scope_clone()
                    , var_name, src_addr.addr_ref());
            },
            _ => {}
        }
    }
}

impl TokenValueExpand for TokenValue {
    /*
    fn to_type(&self) -> Type {
        match self.token_type_clone() {
            TokenType::Const(t) => {
                Type::new(TypeValue::Primeval(Primeval::new(
                            t)), TypeAttrubute::Ref/*TODO*/)
            },
            TokenType::True => {
            },
            TokenType::False => {
            },
            _ => {
                unimplemented!();
            }
        }
    }
    */

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
    fn to_type<F: Compile>(self, cp: RefPtr) -> Result<Type, DescResult> {
        match self {
            TypeToken::Single(tv) => {
                let token_data = tv.token_data().expect("should not happend");
                let t = extract_token_data!(token_data, Id);
                match Type::from_str(&t) {
                    Some(typ) => {
                        Ok(typ)
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
                                let struct_obj = StructObject::new(sd.clone());
                                /*
                                println!("xxxxxxxxxxxxx {:?}", struct_obj);
                                struct_obj.as_ref().name_ref();
                                */
                                Ok(Type::new_with_addrtyp(
                                    TypeValue::Structure(Structure::new(struct_obj))
                                    , TypeAddrType::Stack))
                            },
                            None => {
                                return Err(DescResult::Error(format!("undefine type: {:?}", t)));
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
