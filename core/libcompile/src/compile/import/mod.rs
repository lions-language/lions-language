use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{ImportStmtContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_import_stmt(&mut self, context: ImportStmtContext) -> DescResult {
        match &context.prefix {
            ImportPrefixType::Local => {
                return self.import_local(context.content);
            },
            _ => {
                unimplemented!("{:?}", context.prefix);
            }
        }
    }

    fn import_local(&mut self, path: &str) -> DescResult {
        /*
         * 判断路径是否存在
         * */
        if !Path::new(path).exists() {
            return DescResult::Error(
                format!("import path: {:?} is not found", path));
        }
        DescResult::Success
    }
}

