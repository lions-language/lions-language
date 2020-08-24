use libcommon::ptr::{RefPtr};
use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{FunctionReturn
    , FunctionReturnDataAttr
    , FunctionReturnRefParam};
use libtype::{PackageType, PackageTypeValue
    , AddressType, AddressValue
    , AddressKey
    , Type, TypeAttrubute};
use libtype::instruction::{Jump, RemoveOwnership};
use libgrammar::grammar::{ReturnStmtContext as GrammarReturnStmtContext};
use libresult::{DescResult};
use crate::address::Address;
use crate::compile::{Compile, Compiler, ReturnStmtContext
    , AddressValueExpand};
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

    fn return_stmt_ref_process(&mut self, scope: usize
        , mut func_return_ptr: RefPtr, addr: AddressValue) -> DescResult {
        /*
         * NOTE
         *  1. 如果引用的输入参数不是引用类型, 那么将报错
         *      因为, 如果返回了一个具有所有权的参数, 那么作用域结束的时候是会被释放的
         *      那么将导致内存访问错误
         * */
        /*
        let (expr_addr_index, expr_addr_offset, expr_addr_lengthen_offset, _) = addr.fields_move();
        let expr_addr_index = expr_addr_index as usize;
        let func_return = func_return_ptr.as_mut::<FunctionReturn>();
        let func_return_data = func_return.data_mut();
        let func_params = self.scope_context.last_n_unchecked(scope)
            .get_all_func_param_addr_index_ref();
        let fps = match func_params {
            Some(fps) => {
                fps
            },
            None => {
                return DescResult::Error(
                    format!("return is a ref, but not exist params"));
            }
        };
        let mut ref_param_index = None;
        for (i, (addr_index, typ_attr)) in fps.iter().enumerate() {
            if *addr_index == expr_addr_index {
                /*
                 * 返回值引用的是这个参数 => 判断该参数是否是移动
                 * 如果是移动, 报错 => 不能返回局部变量的引用
                 * */
                if typ_attr.is_move() {
                    return DescResult::Error(
                        format!("cannot return references to local variables
                            , param index: {:?}", i));
                }
                ref_param_index = Some(i);
                break;
            }
        }
        /*
         * 更新函数返回值声明中的属性
         * */
        match ref_param_index {
            Some(index) => {
                self.cb.update_func_return_data_addr(
                    FunctionReturnDataAttr::RefParamIndex(
                        (index, expr_addr_offset, expr_addr_lengthen_offset)));
            },
            None => {
            }
        }
        */
        self.cb.update_func_return_data_addr(
            FunctionReturnDataAttr::RefParam(
                FunctionReturnRefParam::Addr(addr.clone())));
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
            let func_return = self.scope_context.last_n_mut_unchecked(scope).func_return_mut()
                .as_mut().expect("should not happend");
            /*
             * 如果是 引用, 那么查找返回值数据地址的时候, 在函数调用的上一层作用域中查找
             * 如果是 移动, 就是在当前作用域中查找
             * */
            let find_src_addr = if func_return.data_ref().typ_attr_ref().is_move_as_return() {
                src_addr.addr_ref().clone()
            } else if func_return.data_ref().typ_attr_ref().is_ref_as_return() {
                src_addr.addr_ref().clone_with_scope_plus(1)
            } else {
                unimplemented!();
            };
            // println!("{:?}", find_src_addr);
            self.cb.return_stmt(ReturnStmtContext::new_with_all(
                    scope, find_src_addr));
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
            if func_return_ptr.as_ref::<FunctionReturn>().data_ref()
                .typ_attr_ref().is_move_as_return() {
                self.cb.remove_ownership(RemoveOwnership::new_with_all(
                        src_addr.addr_clone()));
            }
            /*
             * 如果函数声明中的返回值是引用, 需要查找与输入参数中的哪一个地址一致
             * */
            if func_return_ptr.as_ref::<FunctionReturn>()
                .data_ref().typ_attr_ref().is_ref_as_return() {
                match self.return_stmt_ref_process(scope, func_return_ptr.clone()
                    , src_addr) {
                    DescResult::Error(e) => {
                        return DescResult::Error(e);
                    },
                    _ => {}
                }
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
        /*
        */
        DescResult::Success
    }
}
