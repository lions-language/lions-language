use libtype::instruction::Instruction;
use crate::define::FunctionDefine;

impl FunctionDefine {
    pub fn write(&mut self, instructure: Instruction) {
    }
    
    pub fn length_add(&mut self, n: usize) {
        self.length += n;
    }

    pub fn new(start_pos: usize) -> Self {
        Self {
            start_pos: start_pos,
            length: 0
        }
    }
}

