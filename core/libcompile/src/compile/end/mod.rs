use libtype::{PackageType, PackageTypeValue};
use libtype::function::{FindFunctionContext};
use libresult::*;
use crate::compile::{Compile, Compiler, FileType};

impl<F: Compile> Compiler<F> {
    pub fn handle_end(&mut self) -> DescResult {
        if let FileType::Main = self.input_context.attr_ref().file_typ_ref() {
            /*
             * 查找 main 函数的声明
             * 1. main 函数必须在 main.lions 中定义, 否则报错
             * */
            let (exists, _) = self.function_control.is_exists(&FindFunctionContext{
                typ: None,
                package_typ: Some(&PackageType::new(PackageTypeValue::Crate)),
                func_str: "main",
                module_str: self.module_stack.current().name_ref()
            });
            if !exists {
                return DescResult::Error(
                    String::from("the main function must exist in main.lions"));
            }
        };
        DescResult::Success
    }
}

