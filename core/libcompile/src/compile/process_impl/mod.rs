use libresult::{DescResult};
use libtype::instruction::{};
use libgrammar::grammar::{ImplStmtContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_impl_stmt(&mut self, context: ImplStmtContext) -> DescResult {
        self.scope_context.push_with_addr_context_typattr_to_value_buffer(
            var_typ
            , var_addr, buf_ctx
            , at);
        DescResult::Success
    }
}

