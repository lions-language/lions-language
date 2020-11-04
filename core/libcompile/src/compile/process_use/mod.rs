use libresult::{DescResult};
use libtype::instruction::{};
use libgrammar::grammar::{UseStmtContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_use_stmt(&mut self, context: UseStmtContext) -> DescResult {
        /*
         * 如果不是 mod.lions, 就报错
         * */
        match self.input_context.attr_ref().file_typ_ref() {
            FileType::Mod|FileType::RELMOD => {
            },
            _ => {
                return DescResult::Error(
                    format!("use stmt must be use in mod.lions or relmod.lions"));
            }
        }
        let content = context.fields_move();
        /*
         * 1. 检测是否是 *
         * 2. 检测 名字 + .lions 是否存在
         * */
        if content == libcommon::consts::STAR {
            /*
             * 获取所有 *.lions 文件
             * */
        } else {
            let path = Path::new(&content).join(libcommon::consts::LIONS_EXT);
            if !path.exists() {
                return DescResult::Error(
                    format!("use path: {:?} is not found", content));
            }
            if !path.is_file() {
                return DescResult::Error(
                    format!("use path: {:?} is not file", content));
            }
        }
        DescResult::Success
    }
}

