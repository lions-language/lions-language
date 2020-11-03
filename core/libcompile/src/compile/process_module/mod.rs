use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{ModuleStmtContext};
use libgrammar::token::{TokenData};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_module_stmt(&mut self, context: ModuleStmtContext) -> DescResult {
        /*
         * 如果不是 mod.lions, 就报错
         * */
        match self.input_context.attr_ref().file_typ_ref() {
            FileType::Mod => {
            },
            _ => {
                return DescResult::Error(
                    format!("module stmt must be use in mod.lions"));
            }
        }
        /*
         * 将 module name 记录在 package global data 中
         * */
        let module_name = context.fields_move();
        DescResult::Success
    }
}

