use libtype::instruction::Instruction;
use libtype::function::FunctionStatement;
use crate::define::FunctionDefine;
use crate::define::to_be_filled::function::{FuncToBeFilled};

impl FunctionDefine {
    pub fn write(&mut self, instructure: Instruction) {
    }

    pub fn length_add(&mut self, n: usize) {
        self.length += n;
    }

    pub fn new(start_pos: usize, statement: FunctionStatement) -> Self {
        Self {
            start_pos: start_pos,
            length: 0,
            statement: statement,
            to_be_filled: FuncToBeFilled::new()
        }
    }
}

