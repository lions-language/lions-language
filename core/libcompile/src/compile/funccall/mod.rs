use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionDefine, OptcodeFunctionDefinePrepareFn
    , OptcodeFunctionDefine};
use libtype::AddressValue;
use libtype::package::{PackageStr};
use libgrammar::token::{TokenValue, TokenData};
use libresult::*;
use crate::compile::{Compile, Compiler, FileType
    , CallFunctionContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_call_function_optcode(&mut self, param_len: usize
        , obj: &OptcodeFunctionDefine) -> DescResult {
        if let Some(f) = obj.prepare_fn_ref() {
        };
        DescResult::Success
    }

    pub fn handle_call_function(&mut self, param_len: usize
        , mut names: Vec<TokenValue>) -> DescResult {
        /*
         * 1. 查找函数声明
         * */
        let mut package_type = PackageType::new(PackageTypeValue::Unknown);
        let mut typ = None;
        if names.len() == 1 {
            /*
             * 直接是函数名, 没有前缀
             * */
            package_type = PackageType::new(PackageTypeValue::Crate);
        }
        let last = names.pop().expect("should not happend");
        let last_data = last.token_data().expect("should not happend");
        let func_str = extract_token_data!(last_data, Id);
        let find_func_context = FindFunctionContext {
            typ: typ,
            package_typ: if let PackageTypeValue::Unknown = package_type.typ_ref() {
                None
            } else {
                Some(&package_type)
            },
            func_str: &func_str,
            module_str: self.module_stack.current().name_ref()
        };
        let (exists, handle) = self.function_control.is_exists(&find_func_context);
        if exists {
            let h = Some(handle);
            let func_res = self.function_control.find_function(&find_func_context, &h);
            match func_res {
                FindFunctionResult::Success(r) => {
                    match r.func.func_define_ref() {
                        FunctionDefine::Optcode(obj) => {
                            return self.handle_call_function_optcode(param_len, obj);
                        },
                        FunctionDefine::Address(_) => {
                            unimplemented!();
                        }
                    }
                },
                FindFunctionResult::Panic(s) => {
                    return DescResult::Error(s);
                },
                _ => {
                    panic!("should not happend");
                }
            }
        } else {
            return DescResult::Error(
                String::from("the main function must exist in main.lions"));
        }
        DescResult::Success
    }
}

