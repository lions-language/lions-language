use libtype::instruction::{Instruction, Jump};
use std::collections::VecDeque;

pub struct Memory {
    instructions: VecDeque<Instruction>
}

impl Memory {
    pub fn write(&mut self, instruction: Instruction) {
        // println!("{:?}", instruction);
        self.instructions.push_back(instruction);
    }

    pub fn set_jump(&mut self, index: usize, jump: Jump) {
        match self.instructions.get_mut(index) {
            Some(ins) => {
                match ins {
                    Instruction::Jump(jp) => {
                        *jp = jump;
                    },
                    _ => {
                        panic!("should not happend");
                    }
                }
            },
            None => {
                panic!("should not happend");
            }
        }
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

