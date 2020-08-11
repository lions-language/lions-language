use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionDefine, FunctionParamData
    , OptcodeFunctionDefine, FunctionParamLengthenAttr
    , CallFunctionParamAddr, Function, splice::FunctionSplice
    , FunctionReturnDataAttr, FunctionParamDataItem};
use libtype::AddressValue;
use libtype::package::{PackageStr};
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{CallFuncScopeContext};
use libresult::*;
use libcommon::ptr::RefPtr;
use crate::compile::{Compile, Compiler, FileType
    , CallFunctionContext, value_buffer::ValueBufferItem
    , AddressValueExpand};
use crate::address::Address;
use std::collections::VecDeque;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn binary_type_match(&mut self, input_value: ValueBufferItem, expect_typ: &Type
        , is_auto_call_totype: bool)
        -> Result<AddressValue, DescResult> {
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
                    return Err(DescResult::Error(format!(
                    "expect type: {:?}, but found type: {:?}"
                    , et, it)));
                }
                /*
                 * 需要自动调用 to_#type 方法
                 * 1. 拼接 期望的方法名
                 * */
                let func_name = FunctionSplice::get_to_type_by_type(expect_typ);
                let param = FunctionParamData::Single(FunctionParamDataItem::new(
                    input_typ.clone(), input_value.typ_attr_ref().clone()));
                let expect_func_str = FunctionSplice::get_function_without_return_string_by_type(
                    &func_name, &Some(&param), &Some(input_typ));
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
                    return Err(DescResult::Error(format!(
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
                /*
                 * 将参数地址中的 scope 加1, 告诉虚拟机要从上一个作用域中查找
                 * */
                let param_addrs = vec![CallFunctionParamAddr::Fixed(
                    input_value.addr_ref().addr_ref().clone_with_scope_plus(1))];
                let func_statement = func.func_statement_ref();
                let return_data = &func_statement.func_return.data;
                let mut scope: Option<usize> = None;
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
                                 *  返回值地址中的 scope 需要分配为1,
                                 *  因为返回值需要绑定到前一个作用域中
                                 * */
                                scope = Some(1);
                                let a = self.scope_context.alloc_address(
                                    return_data.typ.to_address_type(), 1);
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
                    return_addr: return_addr.addr_clone()
                };
                self.call_function_and_ctrl_scope(call_context);
                /*
                 * 因为地址被修改, 所以返回修改后的地址 (调用 to_#type 后的 return 地址)
                 *  作用域结束之后, 如果之前修改过scope, 需要减掉
                 * */
                match scope {
                    Some(n) => {
                        return Ok(return_addr.addr().addr_with_scope_minus(n));
                    },
                    None => {
                        return Ok(return_addr.addr());
                    }
                }
            }
        }
        /*
         * 返回输入的地址
         * */
        Ok(input_value.addr().addr())
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
                                        // let value_addr = value.addr_ref().addr_clone();
                                        let value_addr = match self.binary_type_match(
                                            value, item_typ
                                            , *item.is_auto_call_totype_ref()) {
                                            Ok(addr) => {
                                                addr
                                            },
                                            Err(e) => {
                                                return e;
                                            }
                                        };
                                        /*
                                         * 将参数地址中的 scope 加1,
                                         * 告诉虚拟机要从上一个作用域中查找
                                         * */
                                        params_addr.push_front(
                                        value_addr.clone_with_scope_plus(1));
                                    }
                                    Some(vec![CallFunctionParamAddr::Lengthen(params_addr)])
                                },
                                FunctionParamLengthenAttr::Fixed => {
                                    /*
                                     * 判断参数的类型是否和函数声明的一致
                                     * */
                                    let value = self.scope_context.take_top_from_value_buffer();
                                    // let value_addr = value.addr_ref().addr_clone();
                                    let value_addr = match self.binary_type_match(
                                        value, item_typ
                                        , *item.is_auto_call_totype_ref()) {
                                        Ok(addr) => {
                                            addr
                                        },
                                        Err(e) => {
                                            return e;
                                        }
                                    };
                                    /*
                                     * 参数正确 => 构建参数地址列表
                                     * */
                                    Some(vec![CallFunctionParamAddr::Fixed(
                                            value_addr.clone_with_scope_plus(1))])
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
                return_addr: return_addr.addr_clone()
            };
            self.call_function_and_ctrl_scope(call_context);
            /*
             * 获取返回类型, 将其写入到队列中
             * */
            if !return_addr.is_invalid() {
                self.scope_context.push_with_addr_to_value_buffer(
                    return_data.typ.clone()
                    , return_addr);
            }
        } else {
            return DescResult::Error(
                String::from("the main function must exist in main.lions"));
        }
        DescResult::Success
    }
}

