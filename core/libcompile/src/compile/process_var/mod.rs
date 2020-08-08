use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_var_stmt_start(&mut self, id_token: TokenValue) {
        /*
         * 为变量分配内存
         * */
    }

    pub fn handle_var_stmt_equal(&mut self) {
    }

    pub fn handle_var_stmt_end(&mut self) {
    }
}
