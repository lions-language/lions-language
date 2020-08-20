use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue
    , AddressType, AddressValue
    , Type, TypeAttrubute};
use libgrammar::grammar::{ReturnStmtContext as GrammarReturnStmtContext};
use libresult::{DescResult};
use crate::address::Address;
use crate::compile::{Compile, Compiler, ReturnStmtContext};
use crate::compile::scope::vars::Variant;
use crate::compile::scope::{ScopeType};
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_return_stmt(&mut self, context: GrammarReturnStmtContext) -> DescResult {
        if context.is_exist_expr_clone() {
            /*
             * 存在表达式
             * */
            let value = self.scope_context.take_top_from_value_buffer();
            let typ = value.typ_ref().clone();
            let typ_attr = value.typ_attr_ref().clone();
            let src_addr = value.addr_ref().addr_clone();
            let scope = match self.scope_context.get_last_scope_type_index(
                &ScopeType::Function) {
                Some(scope) => {
                    scope
                },
                None => {
                    return DescResult::Error(
                        format!("return must be in function"));
                }
            };
            self.cb.return_stmt(ReturnStmtContext::new_with_all(
                    scope, src_addr.addr()));
        }
        DescResult::Success
    }
}