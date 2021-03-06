use libresult::DescResult;
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{
    ObjectFunctionDefineMutContext
    , TypeToken};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext
    , FunctionDefineContext};
use crate::compile::scope::ScopeType;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_function_object_method_stmt(&mut self
        , object_type: TypeToken, func_name: TokenValue
        , mut_context: &mut ObjectFunctionDefineMutContext
        , define_context: &mut FunctionDefineContext) -> DescResult {
        self.scope_context.enter(ScopeType::Function);
        let obj_type = match self.to_type(object_type) {
            Ok(ty) => ty,
            Err(err) => {
                return err;
            }
        };
        let s = match func_name.token_data.expect("should not happend") {
            TokenData::Id(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        };
        *mut_context.typ_mut() = obj_type.clone();
        self.cb.function_named_stmt(FunctionNamedStmtContext{
            name: s,
            typ: Some(obj_type)
        }, define_context);
        DescResult::Success
    }
}

