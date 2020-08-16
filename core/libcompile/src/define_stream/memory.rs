use libtype::instruction::Instruction;
use std::collections::VecDeque;

pub struct Memory {
    instructions: VecDeque<Instruction>
}

impl Memory {
    pub fn write(&mut self, instruction: Instruction) {
        // println!("{:?}", instruction);
        self.instructions.push_back(instruction);
    }

    pub fn get(&self, index: usize) -> Option<&Instruction> {
        self.instructions.get(index)
    }

    pub fn get_all_mut(&mut self) -> &mut VecDeque<Instruction> {
        &mut self.instructions
    }

    pub fn length(&self) -> usize {
        self.instructions.len()
    }

    pub fn new() -> Self {
        Self {
            instructions: VecDeque::new()
        }
    }
}

