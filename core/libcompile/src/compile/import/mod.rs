use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{ImportStmtContext};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_import_stmt(&mut self, context: ImportStmtContext) {
    }
}

