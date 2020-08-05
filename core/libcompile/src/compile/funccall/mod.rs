use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionDefine, FunctionParamData
    , OptcodeFunctionDefine, FunctionParamLengthenAttr
    , CallFunctionParamAddr};
use libtype::AddressValue;
use libtype::package::{PackageStr};
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{CallFuncScopeContext};
use libresult::*;
use crate::compile::{Compile, Compiler, FileType
    , CallFunctionContext};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
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
            let func = match func_res {
                FindFunctionResult::Success(r) => {
                    r.func
                },
                FindFunctionResult::Panic(s) => {
                    return DescResult::Error(s);
                },
                _ => {
                    panic!("should not happend");
                }
            };
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
                            /*
                             * 只有一个参数, 判断该参数是不是变长参数
                             * */
                            match item.lengthen_attr_ref() {
                                FunctionParamLengthenAttr::Lengthen => {
                                    /*
                                     * 函数需要一个变长的参数
                                     * 将 param_len 个参数从 value_buffer 中取出
                                     * */
                                    unimplemented!();
                                },
                                FunctionParamLengthenAttr::Fixed => {
                                    /*
                                     * 判断参数的类型是否和函数声明的一致
                                     * */
                                    let value = self.scope_context.take_top_from_value_buffer();
                                    let value_typ = value.typ_ref().typ_ref();
                                    let item_typ = item.typ_ref().typ_ref();
                                    if value_typ != item_typ {
                                        /*
                                         * 类型不匹配 => 报错
                                         * */
                                        return DescResult::Error(format!(
                                        "expect type: {:?}, but found type: {:?}"
                                        , item_typ, value_typ));
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

