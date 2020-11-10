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
    undef_funcs: UndefFuncs,
    inited: bool
}

impl ModuleItem {
    fn set_module(&mut self, module: Module) {
        *&mut self.module = module;
        self.inited = true;
    }

    pub fn new_null() -> Self {
        Self {
            module: Module::default(),
            undef_funcs: UndefFuncs::new(),
            inited: false
        }
    }

    pub fn new(module: Module) -> Self {
        Self {
            module: module,
            undef_funcs: UndefFuncs::new(),
            inited: true
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

    pub fn push_null(&mut self) {
        self.stack.push(ModuleItem::new_null());
    }

    pub fn pop(&mut self) -> Option<ModuleItem> {
        self.stack.pop()
    }

    pub fn set_current_module(&mut self, module: Module) {
        *&mut self.stack.top_mut_unchecked().set_module(module);
    }

    pub fn current_module_is_valid(&mut self) -> bool {
        match self.stack.top_ref() {
            Some(item) => {
                item.inited.clone()
            },
            None => {
                false
            }
        }
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

