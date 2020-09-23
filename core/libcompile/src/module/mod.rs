use libtype::module::{Module};

pub struct ModuleStack {
    stack: Vec<Module>
}

impl ModuleStack {
    pub fn current(&self) -> &Module {
        self.stack.last().expect("should not happend")
    }

    pub fn new(first: Module) -> Self {
        Self {
            stack: vec![first]
        }
    }
}
