use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionDefine, FunctionParamData
    , OptcodeFunctionDefine, FunctionParamLengthenAttr
    , CallFunctionParamAddr, Function, splice::FunctionSplice
    , FunctionReturnDataAttr};
use libtype::AddressValue;
use libtype::package::{PackageStr};
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{CallFuncScopeContext};
use libresult::*;
use libcommon::ptr::RefPtr;
use crate::compile::{Compile, Compiler, FileType
    , CallFunctionContext, value_buffer::ValueBufferItem};
use crate::address::Address;
use std::collections::VecDeque;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn binary_type_match(&mut self, input_value: ValueBufferItem, expect_typ: &Type
        , is_auto_call_totype: bool)
        -> (bool, DescResult) {
        let input_typ = input_value.typ_ref();
        let et = expect_typ.typ_ref();
        let it = input_typ.typ_ref();
        if !et.is_any() {
            /*
             * 不是 any 的情况下才需要判断类型
             * */
            if it != et {
                /*
                 * 类型不匹配
                 *  1. 判断是否需要自动调用 to_#type 方法
                 *    需要转换:
                 *      查找需要转换的函数是否存在
                 *      比如说: expect_typ 是 string 类型, 那么查找 input_typ 中是否存在 to_string
                 *      方法
                 * */
                if !is_auto_call_totype {
                    return (false, DescResult::Error(format!(
                    "expect type: {:?}, but found type: {:?}"
                    , et, it)));
                }
                /*
                 * 需要自动调用 to_#type 方法
                 * 1. 拼接 期望的方法名
                 * */
                let expect_func_str = FunctionSplice::get_to_type_by_type(expect_typ);
                /*
                 * 查找方法
                 * */
                let find_func_context = FindFunctionContext {
                    typ: Some(input_typ),
                    package_typ: input_value.package_type_ref().as_ref(),
                    func_str: &expect_func_str,
                    module_str: self.module_stack.current().name_ref()
                };
                let (exists, handle) = self.function_control.is_exists(&find_func_context);
                if !exists {
                    return (false, DescResult::Error(format!(
                    "expect type: {:?}, but found type: {:?}, and not find func: {} in {:?}"
                    , et, it, expect_func_str, it)));
                }
                /*
                 * 方法存在 => 调用方法
                 * */
                let h = Some(handle);
                let func_res = self.function_control.find_function(&find_func_context, &h);
                let func_ptr = match func_res {
                    FindFunctionResult::Success(r) => {
                        RefPtr::from_ref(r.func)
                    },
                    _ => {
                        panic!("should not happend");
                    }
                };
                let func = func_ptr.as_ref::<Function>();
                let param_addrs = vec![CallFunctionParamAddr::Fixed(input_value.addr_ref().addr_clone())];
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
                        match return_data.typ.attr_ref() {
                            TypeAttrubute::Move => {
                                match &return_data.attr {
                                    FunctionReturnDataAttr::Create => {
                                        /*
                                         * 一定是创建: FunctionReturnDataAttr::Create
                                         * */
                                    },
                                    _ => {
                                        panic!("should not happend")
                                    }
                                }
                                /*
                                 * 根据类型, 判断是在哪里分配地址
                                 * */
                                let a = self.scope_context.alloc_address(
                                    return_data.typ.to_address_type());
                                self.scope_context.ref_counter_create(a.addr_ref().addr_clone());
                                a
                            },
                            _ => {
                                /*
                                 * to_#type 方法一定返回的是一个 Move, 所以这里不会到达
                                 * */
                                panic!("should not happend")
                            }
                        }
                    }
                };
                let call_context = CallFunctionContext {
                    package_str: input_value.package_str(),
                    func: &func,
                    param_addrs: Some(param_addrs),
                    return_addr: return_addr.addr()
                };
                self.call_function_and_ctrl_scope(call_context);
            }
        }
        (true, DescResult::Success)
    }

    pub fn handle_call_function(&mut self, call_scope_context: CallFuncScopeContext
        , name: TokenValue, param_len: usize) -> DescResult {
        /*
         * 1. 查找函数声明
         * */
        let name_data = name.token_data().expect("should not happend");
        let func_str = extract_token_data!(name_data, Id);
        let find_func_context = FindFunctionContext {
            typ: call_scope_context.typ_ref().as_ref(),
            package_typ: call_scope_context.package_type_ref().as_ref(),
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
                            let item_typ = item.typ_ref();
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
                                        let value_addr = value.addr_ref().addr_clone();
                                        let (b, e) = self.binary_type_match(
                                            value, item_typ
                                            , *item.is_auto_call_totype_ref());
                                        if !b {
                                            return e;
                                        }
                                        params_addr.push_front(
                                        value_addr);
                                    }
                                    Some(vec![CallFunctionParamAddr::Lengthen(params_addr)])
                                },
                                FunctionParamLengthenAttr::Fixed => {
                                    /*
                                     * 判断参数的类型是否和函数声明的一致
                                     * */
                                    let value = self.scope_context.take_top_from_value_buffer();
                                    let value_addr = value.addr_ref().addr_clone();
                                    let (b, e) = self.binary_type_match(
                                        value, item_typ
                                        , *item.is_auto_call_totype_ref());
                                    if !b {
                                        return e;
                                    }
                                    /*
                                     * 参数正确 => 构建参数地址列表
                                     * */
                                    Some(vec![CallFunctionParamAddr::Fixed(value_addr)])
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
                package_str: call_scope_context.package_str(),
                func: &func,
                param_addrs: param_addrs,
                return_addr: return_addr.addr()
            };
            self.call_function_and_ctrl_scope(call_context);
        } else {
            return DescResult::Error(
                String::from("the main function must exist in main.lions"));
        }
        DescResult::Success
    }
}

