use libtype::module::{Module};
use libcommon::datastructure::stack::Stack;
use libmacro::{FieldGet, FieldGetMove};
use std::collections::HashMap;

pub struct UndefineFunction {
}

pub struct UndefFuncs {
    funcs: HashMap<String, UndefineFunction>
}

#[derive(FieldGet, FieldGetMove)]
pub struct ModuleItem {
    module: Module,
    undef_funcs: UndefFuncs,
    inited: bool
}

impl ModuleItem {
    fn init_module(&mut self) {
        self.inited = true;
    }

    pub fn new(module: Module) -> Self {
        Self {
            module: module,
            undef_funcs: UndefFuncs::new(),
            inited: false
        }
    }
}

pub struct ModuleStack {
    stack: Stack<ModuleItem>
}

impl ModuleStack {
    pub fn current(&self) -> &Module {
        /*
         * 这里不需要计算完整路径, 因为在 push 的时候, 已经将完整路径 push 到 module_stack 中了
         * */
        &self.stack.top_ref_unchecked().module
    }

    pub fn current_mut(&mut self) -> &mut Module {
        &mut self.stack.top_mut_unchecked().module
    }

    pub fn push(&mut self, module: Module) {
        self.stack.push(ModuleItem::new(module));
    }

    pub fn pop(&mut self) -> Option<ModuleItem> {
        self.stack.pop()
    }

    pub fn init_current_module(&mut self) {
        *&mut self.stack.top_mut_unchecked().init_module();
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

pub struct ModuleMapping {
    /*
     * key: module_str
     * value: module_name
     * */
    str_name: HashMap<String, String>
}

impl ModuleMapping {
    pub fn add(&mut self, module_str: String, module_name: String) {
        self.str_name.insert(module_str, module_name);
    }

    pub fn get(&self, module_str: &str) -> Option<&String> {
        self.str_name.get(module_str)
    }

    pub fn new() -> Self {
        Self {
            str_name: HashMap::new()
        }
    }
}

mod undefine_function;

