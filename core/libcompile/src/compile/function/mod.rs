use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_function_named_stmt(&mut self, value: TokenValue) {
        let s = match value.token_data.expect("should not happend") {
            TokenData::Id(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        };
        self.cb.function_named_stmt(FunctionNamedStmtContext{
            name: s
        });
    }

    pub fn handle_function_define_param(&mut self, name_token: TokenValue
        , type_token: TokenValue) {
        /*
         * 1. 生成参数加载指令
         * 2. 填充函数声明
         * */
    }

    pub fn handle_function_define_end(&mut self) {
        let func = self.cb.function_define_end();
        let package_typ = PackageType::new(PackageTypeValue::Crate);
        let context = AddFunctionContext{
            typ: None,
            package_typ: Some(&package_typ),
            module_str: self.module_stack.current().to_str().to_string(),
            func_str: func.func_statement_ref().func_name.clone()
        };
        self.function_control.add_function(context, None, func);
    }
}
