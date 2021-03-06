use libmacro::{FieldGet, FieldGetClone, FieldGetMove};

#[derive(Default, FieldGet, FieldGetClone
    , FieldGetMove, Debug)]
pub struct Module {
    name: String,
    module_str: String
}

impl Module {
    pub fn new_module_str(module_str: String) -> Self {
        Module::new(String::default(), module_str)
    }

    pub fn new(name: String, module_str: String) -> Self {
        Self {
            name: name,
            module_str: module_str
        }
    }
}

mod module;

