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

    fn import_local(&mut self, content: &str) -> DescResult {
        /*
         * 检测路径是否是目录
         * */
        let path = Path::new(content);
        if !path.exists() {
            return DescResult::Error(
                format!("import path: {:?} is not found", content));
        }
        if !path.is_dir() {
            return DescResult::Error(
                format!("import path: {:?} is not dir", content));
        }
        /*
         * 检测路径是否包含 mod.lions
         * */
        if !path.join(libcommon::consts::MOD_LIONS_NAME).as_path().exists() {
            return DescResult::Error(
                format!("{} does not exist in the path of import"
                    , libcommon::consts::MOD_LIONS_NAME));
        }
        DescResult::Success
    }
}

