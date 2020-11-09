use libtype::module::{Module};
use libcommon::datastructure::stack::Stack;
use std::collections::HashMap;

pub struct UndefineFunction {
}

pub struct UndefFuncs {
    funcs: HashMap<String, UndefineFunction>
}

pub struct ModuleItem {
    module: Module,
    undef_funcs: UndefFuncs
}

impl ModuleItem {
    pub fn new(module: Module) -> Self {
        Self {
            module: module,
            undef_funcs: UndefFuncs::new()
        }
    }
}

pub struct ModuleStack {
    stack: Stack<ModuleItem>
}

impl ModuleStack {
    pub fn current(&self) -> &Module {
        &self.stack.top_ref_unchecked().module
    }

    pub fn push(&mut self, module: Module) {
        self.stack.push(ModuleItem::new(module));
    }

    pub fn pop(&mut self) -> Option<ModuleItem> {
        self.stack.pop()
    }

    pub fn new_with_first(first: Module) -> Self {
        let mut stack = Stack::new();
        stack.push(ModuleItem::new(first));
        Self {
            stack: stack
        }
    }

    pub fn new() -> Self {
        Self {
            stack: Stack::new()
        }
    }
}

mod undefine_function;

