use libcommon::ptr::{RefPtr};
use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{FunctionReturn};
use libtype::{PackageType, PackageTypeValue
    , AddressType, AddressValue
    , Type, TypeAttrubute};
use libtype::instruction::{Jump, RemoveOwnership};
use libgrammar::grammar::{ReturnStmtContext as GrammarReturnStmtContext};
use libresult::{DescResult};
use crate::address::Address;
use crate::compile::{Compile, Compiler, ReturnStmtContext};
use crate::compile::scope::vars::Variant;
use crate::compile::scope::{ScopeType};
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    fn return_stmt_check(&self, func_return_ptr: RefPtr
        , input_typ: &Type, input_typ_attr: &TypeAttrubute) -> DescResult {
        let func_return = func_return_ptr.as_ref::<FunctionReturn>();
        let func_return_data = func_return.data_ref();
        if func_return_data.typ_ref().typ_ref() != input_typ.typ_ref() {
            return DescResult::Error(
                format!("expect return type: {:?}, but found return type: {:?}"
                    , func_return_data.typ_ref().typ_ref(), input_typ.typ_ref()));
        }
        if func_return_data.typ_attr_ref() != input_typ_attr {
            return DescResult::Error(
                format!("expect return type attr: {:?}, but found return type attr: {:?}"
                    , func_return_data.typ_attr_ref(), input_typ_attr));
        }
        DescResult::Success
    }

    pub fn handle_return_stmt(&mut self, context: GrammarReturnStmtContext) -> DescResult {
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
        if context.is_exist_expr_clone() {
            /*
             * 存在表达式
             * */
            let value = self.scope_context.take_top_from_value_buffer();
            let typ = value.typ_ref().clone();
            let typ_attr = value.typ_attr_ref().clone();
            let src_addr = value.addr_ref().addr_clone();
            self.cb.return_stmt(ReturnStmtContext::new_with_all(
                    scope, src_addr.addr_clone()));
            let func_return = self.scope_context.last_n_mut_unchecked(scope).func_return_mut()
                .as_mut().expect("should not happend");
            /*
             * 检测表达式结果和函数声明是否一致
             * */
            let func_return_ptr = RefPtr::from_ref(func_return);
            match self.return_stmt_check(func_return_ptr.clone()
                , &typ, &typ_attr) {
                DescResult::Error(e) => {
                    return DescResult::Error(e);
                },
                _ => {}
            }
            /*
             * 如果函数声明中的返回值是移动的, 需要返回地址
             * */
            if func_return_ptr.as_ref::<FunctionReturn>().data_ref().typ_attr_ref().is_move() {
                self.cb.remove_ownership(RemoveOwnership::new_with_all(
                        src_addr.addr()));
            }
        }
        /*
         * 生成 Jump 指令
         * */
        let jump_index = self.cb.jump(Jump::default());
        /*
         * 因为 Jump 指令实际的跳转位置现在无法获知, 所以需要等待函数定义结束才能填充
         * 所以, 这里将 Jump 指令的位置记录下来
         * */
        self.scope_context.last_n_mut_unchecked(scope).add_return_jump(jump_index);
        DescResult::Success
    }
}
