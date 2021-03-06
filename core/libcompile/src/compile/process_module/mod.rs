use libresult::{DescResult};
use libtype::instruction::{
    Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libtype::module::{Module};
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
        let (module_name, available_stmt_count, counter_len) = context.fields_move();
        /*
         * module 必须是 mod.lions 文件的第一个有效语句
         * */
        if !(counter_len == 1 && available_stmt_count == 0) {
            return DescResult::Error(
                format!("module stmt must appear on the first line"));
        }
        /*
         * 因为 mod.lions 在 import 的时候写入了 module_stack, 所以这里要更新module_name
         * TODO:
         *  这里需要记录 相对源码根路径的完整 module str
         *      context 中传入当前 mod.lions 的路径; root_path 在 compile 中; 通过 path_diff
         *      找到相差路径
         * */
        self.module_stack.init_current_module();
        *self.module_stack.current_mut().name_mut() = module_name;
        /*
         * 将 module name 记录在 package global data 中
         * */
        DescResult::Success
    }
}

