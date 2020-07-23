use libtype::instruction::{Instruction};

pub struct Item {
}

impl Item {
    pub fn write(&mut self, instruction: Instruction) {
    }
}

pub struct Dispatch {
}

impl Dispatch {
    pub fn new() -> Self {
        Self {
        }
    }
}

mod item;

