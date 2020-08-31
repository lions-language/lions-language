use libtype::{
    TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionParamData
    , FunctionParamLengthenAttr
    , CallFunctionParamAddr, Function, splice::FunctionSplice
    , FunctionReturnDataAttr, FunctionParamDataItem
    , FunctionReturnRefParam
    , CallFunctionReturnData};
use libtype::instruction::{PushParamRef};
use libtype::{AddressValue
    , AddressType};
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{CallFuncScopeContext
    , CallFunctionContext as GrammarCallFunctionContext};
use libresult::*;
use libcommon::ptr::RefPtr;
use crate::compile::{Compile, Compiler
    , CallFunctionContext, value_buffer::ValueBufferItem
    , value_buffer::ValueBufferItemContext
    , AddressValueExpand};
use crate::compile::scope::{ScopeFuncCall};
use crate::address::Address;
use std::collections::VecDeque;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_call_function_prepare(&mut self, call_scope_context: CallFuncScopeContext
        , name: TokenValue, call_context: &mut GrammarCallFunctionContext) -> DescResult {
        self.scope_context.enter_func_call();
        /*
         * 1. 查找函数声明
         * */
        // let name_data = name.token_data().expect("should not happend");
        // let func_str = extract_token_data!(name_data, Id);
        let mut param_typs = call_context.param_typs_clone();
        let mut func_param_data = None;
        let param_typs_len = param_typs.len();
        if param_typs_len == 1 {
            let (typ, typ_attr) = param_typs.remove(0);
            func_param_data = Some(FunctionParamData::Single(
                FunctionParamDataItem::new(typ, typ_attr)));
        } else if param_typs_len > 1 {
            let mut items = Vec::new();
            while !param_typs.is_empty() {
                let (typ, typ_attr) = param_typs.remove(0);
                items.push(FunctionParamDataItem::new(typ, typ_attr));
            }
            func_param_data = Some(FunctionParamData::Multi(items));
        }
        let func_name = call_context.func_name_ref().as_ref().expect(
            "call_context.func_name_ref(): should not happend").as_ref();
        let func_str = FunctionSplice::get_function_without_return_string_by_type(
            func_name
            , &func_param_data.as_ref(), &call_context.typ_ref().as_ref());
        let find_func_context = FindFunctionContext {
            func_name: func_name,
            typ: call_scope_context.typ_ref().as_ref(),
            package_typ: call_scope_context.package_type_ref().as_ref(),
            func_str: &func_str,
            module_str: self.module_stack.current().name_ref()
        };
        call_context.set_desc_ctx(call_scope_context.desc_ctx_clone());
        let (exists, handle) = self.function_control.is_exists(&find_func_context);
        if exists {
            let h = Some(handle);
            let func_res = self.function_control.find_function(&find_func_context, &h);
            let func_ptr = match func_res {
                FindFunctionResult::Success(r) => {
                    RefPtr::from_ref(r.func)
                },
                FindFunctionResult::Panic(s) => {
                    return DescResult::Error(s);
                },
                _ => {
                    panic!("should not happend");
                }
            };
            call_context.set_func_ptr(func_ptr);
            call_context.set_package_str(call_scope_context.package_str());
        } else {
            let (package_type, package_str, _, typ) = call_scope_context.fields_move();
            call_context.set_typ(typ);
            call_context.set_func_name(func_str);
            call_context.set_package_str(package_str);
            call_context.set_package_typ(package_type);
            /*
            return DescResult::Error(
                format!("the {} function is not found", func_str));
            */
        }
        DescResult::Success
    }

    pub fn handle_call_function_param_before_expr(&mut self, index: usize
        , call_context: &mut GrammarCallFunctionContext) {
        let func_ptr = call_context.func_ptr_clone();
        if func_ptr.is_null() {
            return;
        }
        /*
         * 在当前函数被调用的时候, 只有内置函数才能找到函数的声明
         * 因为内置函数只检测函数名, 而不检测函数参数
         * */
        let func = func_ptr.as_ref::<Function>();
        let func_statement = func.func_statement_ref();
        match func_statement.func_param_ref() {
            Some(fp) => {
                /*
                 * 存在参数
                 * */
                match fp.data_ref() {
                    FunctionParamData::Single(item) => {
                        let item_typ = item.typ_ref().clone();
                        let is_auto_call_totype = *item.is_auto_call_totype_ref();
                        self.scope_context.set_current_func_call(ScopeFuncCall::new_with_all(
                                is_auto_call_totype, item_typ));
                        // println!("{:?}", &self.compile_context);
                        /*
                         * 只有一个参数, 不管 index 是什么, 都以 该参数信息计算
                         * */
                    },
                    FunctionParamData::Multi(items) => {
                        let param_len = func_statement.get_func_param_len();
                        /*
                         * 如果 index > param_len => 说明最后一个是变长参数
                         * 那么当 index < param_len 的时候, 按照 items[index] 进行计算
                         * 否则, 按照 items 的最后一个元素进行计算
                         * */
                    }
                }
            },
            None => {
            }
        }
    }

    pub fn handle_call_function_param_after_expr(&mut self, index: usize
        , call_context: &mut GrammarCallFunctionContext) {
        let func_ptr = call_context.func_ptr_clone();
        if !func_ptr.is_null() {
            /*
             * 已经找到了函数名, 那么不需要解析类型
             * */
            return;
        }
        let value = self.scope_context.top_n_with_panic_from_value_buffer(1);
        call_context.push_param_typ(value.typ_clone(), value.typ_attr_clone());
    }

    pub fn handle_call_function_get_top_addr(&mut self
        , item: &FunctionParamDataItem)
         -> Result<(Type, TypeAttrubute, AddressValue, ValueBufferItemContext), DescResult> {
        let value = self.scope_context.take_top_from_value_buffer();
        let value_context = value.context_clone();
        // let value_addr = value.addr_ref().addr_clone();
        let value_typ_attr = value.typ_attr_clone();
        match self.binary_type_match(
            value, item.typ_ref()
            , *item.is_auto_call_totype_ref()) {
            Ok(v) => {
                let ta = if value_typ_attr.is_ref() {
                    value_typ_attr
                } else {
                    v.1
                };
                Ok((v.0, ta, v.2, value_context))
            },
            Err(e) => {
                Err(e)
            }
        }
        // Ok(addr_value.clone_with_scope_plus(1))
        /*
        Ok(self.process_param(
            &typ, &typ_attr, addr_value, 0, value_context))
        */
    }
}

mod to_type;
mod call;

