use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionDefine, FunctionParamData
    , OptcodeFunctionDefine, FunctionParamLengthenAttr
    , CallFunctionParamAddr, Function};
use libtype::AddressValue;
use libtype::package::{PackageStr};
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{CallFuncScopeContext};
use libresult::*;
use libcommon::ptr::RefPtr;
use crate::compile::{Compile, Compiler, FileType
    , CallFunctionContext};
use crate::address::Address;
use std::collections::VecDeque;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn binary_type_match(&self, input_typ: &TypeValue, expect_typ: &TypeValue)
        -> (bool, DescResult) {
        if !expect_typ.is_any() {
            /*
             * 不是 any 的情况下才需要判断类型
             * */
            if input_typ != expect_typ {
                /*
                 * 类型不匹配 => 报错
                 * */
                return (false, DescResult::Error(format!(
                "expect type: {:?}, but found type: {:?}"
                , input_typ, expect_typ)));
            }
        }
        (true, DescResult::Success)
    }

    pub fn handle_call_function(&mut self, scope_context: CallFuncScopeContext
        , name: TokenValue, param_len: usize) -> DescResult {
        /*
         * 1. 查找函数声明
         * */
        let name_data = name.token_data().expect("should not happend");
        let func_str = extract_token_data!(name_data, Id);
        let find_func_context = FindFunctionContext {
            typ: scope_context.typ_ref().as_ref(),
            package_typ: if let PackageTypeValue::Unknown =
                scope_context.package_type_ref().typ_ref() {
                None
            } else {
                Some(scope_context.package_type_ref())
            },
            func_str: &func_str,
            module_str: self.module_stack.current().name_ref()
        };
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
            let func = func_ptr.as_ref::<Function>();
            let func_statement = func.func_statement_ref();
            let return_data = &func_statement.func_return.data;
            let return_addr = match return_data.typ_ref().typ_ref() {
                TypeValue::Empty => {
                    /*
                     * 如果返回值是空的, 那么就没有必要分配内存
                     * (不过对于 plus 操作, 一定是要有返回值的, 不会到达这里)
                     * */
                    Address::new(AddressValue::new_invalid())
                },
                _ => {
                    unimplemented!();
                }
            };
            let param_addrs = match func_statement.func_param_ref() {
                Some(fp) => {
                    /*
                     * 存在参数
                     * */
                    match fp.data_ref() {
                        FunctionParamData::Single(item) => {
                            let item_typ = item.typ_ref().typ_ref();
                            /*
                             * 只有一个参数, 判断该参数是不是变长参数
                             * */
                            match item.lengthen_attr_ref() {
                                FunctionParamLengthenAttr::Lengthen => {
                                    /*
                                     * 函数需要一个变长的参数
                                     * 将 param_len 个参数从 value_buffer 中取出
                                     *  1. 因为只有一个参数,
                                     *     所以调用时候所有的参数都是这个可变参数的值
                                     * */
                                    let mut params_addr = VecDeque::with_capacity(param_len);
                                    for _ in 0..param_len {
                                        let value = self.scope_context.take_top_from_value_buffer();
                                        let (b, e) = self.binary_type_match(
                                            value.typ_ref().typ_ref(), item_typ);
                                        if !b {
                                            return e;
                                        }
                                        params_addr.push_front(
                                        value.addr().addr());
                                    }
                                    Some(vec![CallFunctionParamAddr::Lengthen(params_addr)])
                                },
                                FunctionParamLengthenAttr::Fixed => {
                                    /*
                                     * 判断参数的类型是否和函数声明的一致
                                     * */
                                    let value = self.scope_context.take_top_from_value_buffer();
                                    if !item_typ.is_any() {
                                        let (b, e) = self.binary_type_match(
                                            value.typ_ref().typ_ref(), item_typ);
                                        if !b {
                                            return e;
                                        }
                                    }
                                    /*
                                     * 参数正确 => 构建参数地址列表
                                     * */
                                    Some(vec![CallFunctionParamAddr::Fixed(value.addr().addr())])
                                }
                            }
                        },
                        FunctionParamData::Multi(_) => {
                            unimplemented!();
                        }
                    }
                },
                None => {
                    None
                }
            };
            let call_context = CallFunctionContext {
                package_str: scope_context.package_str(),
                func: &func,
                param_addrs: param_addrs,
                return_addr: return_addr.addr()
            };
            self.cb.call_function(call_context);
        } else {
            return DescResult::Error(
                String::from("the main function must exist in main.lions"));
        }
        DescResult::Success
    }
}

