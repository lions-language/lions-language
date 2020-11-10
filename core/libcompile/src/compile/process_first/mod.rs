use libresult::{DescResult};
use libtype::module::{Module};
use libgrammar::grammar::{FirstStmtContext};
use libgrammar::token::{TokenData};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_first_stmt(&mut self, context: FirstStmtContext) -> DescResult {
        match self.input_context.attr_ref().file_typ_ref() {
            FileType::Mod => {
                /*
                 * 第一条语句必须是 module
                 * */
                if !self.module_stack.current_module_is_valid() {
                    return DescResult::Error(
                        format!("module stmt must be exists"));
                }
            },
            _ => {
            }
        }
        DescResult::Success
    }
}


