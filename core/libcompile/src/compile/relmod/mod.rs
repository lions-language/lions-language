use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{RelmodStmtContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_relmod_stmt(&mut self, context: RelmodStmtContext) -> DescResult {
        /*
         * 如果不是 mod.lions, 就报错
         * */
        match self.input_context.attr_ref().file_typ_ref() {
            FileType::Mod => {
            },
            _ => {
                return DescResult::Error(
                    format!("relmod stmt must be use in mod.lions"));
            }
        }
        DescResult::Success
    }
}

