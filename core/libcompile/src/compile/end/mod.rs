use libtype::{PackageType, PackageTypeValue};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , Function, CallFunctionReturnData};
use libtype::AddressValue;
use libtype::package::{PackageStr};
use libcommon::ptr::{RefPtr};
use libresult::*;
use crate::compile::{Compile, Compiler, FileType
    , CallFunctionContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_end(&mut self) -> DescResult {
        if let FileType::Main = self.input_context.attr_ref().file_typ_ref() {
            /*
             * 查找 main 函数的声明
             * 1. main 函数必须在 main.lions 中定义, 否则报错
             * */
            let package_typ = PackageType::new(PackageTypeValue::Crate);
            let context = FindFunctionContext{
                typ: None,
                package_typ: Some(&package_typ),
                func_str: "main",
                module_str: self.module_stack.current().name_ref()
            };
            let (exists, handle) = self.function_control.is_exists(&context);
            if exists {
                let h = Some(handle);
                let func_res = self.function_control.find_function(&context, &h);
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
                match func.func_define_ref() {
                    libtype::function::FunctionDefine::Address(addr) => {
                        /*
                         * 函数调用
                         * */
                        let call_context = CallFunctionContext {
                            package_str: PackageStr::Itself,
                            func: &func,
                            param_addrs: None,
                            return_data: CallFunctionReturnData::default()
                        };
                        self.cb.call_function(call_context);
                    },
                    _ => {
                        panic!("should not happend");
                    }
                }
            } else {
                return DescResult::Error(
                    String::from("the main function must exist in main.lions"));
            }
        };
        DescResult::Success
    }
}

