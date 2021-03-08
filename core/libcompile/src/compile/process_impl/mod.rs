use libresult::{DescResult};
use libtype::instruction::{};
use libgrammar::grammar::{ImplStmtContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_impl_stmt(&mut self, context: ImplStmtContext) -> DescResult {
        DescResult::Success
    }
}

