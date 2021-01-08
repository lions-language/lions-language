use libresult::{DescResult};
use libtype::instruction::{
    Instruction, Jump
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
        /*
         * 检测路径是否是目录
         * */
        let content = context.fields_move();
        let path = Path::new(&content);
        if !path.exists() {
            return DescResult::Error(
                format!("relmod path: {:?} is not found", content));
        }
        if !path.is_dir() {
            return DescResult::Error(
                format!("relmod path: {:?} is not dir", content));
        }
        /*
         * 检测路径是否包含 mod.lions, 如果存在就报错 (relmod 指定的目录不能含有其他 mod)
         * */
        if path.join(libcommon::consts::MOD_LIONS_NAME).as_path().exists() {
            return DescResult::Error(
                format!("{} cannot exist in the directory specified by relmod"
                    , libcommon::consts::MOD_LIONS_NAME));
        }
        DescResult::Success
    }
}

