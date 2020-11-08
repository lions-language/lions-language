use libtype::module::{Module};
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
    stack: Vec<ModuleItem>
}

impl ModuleStack {
    pub fn current(&self) -> &Module {
        &self.stack.last().expect("should not happend").module
    }

    pub fn new_with_first(first: Module) -> Self {
        Self {
            stack: vec![ModuleItem::new(first)]
        }
    }

    pub fn new() -> Self {
        Self {
            stack: Vec::new()
        }
    }
}

mod undefine_function;

