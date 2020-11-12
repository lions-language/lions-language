use std::collections::HashMap;

pub struct ImportsMapping {
    imports: HashMap<String, String>
}

impl ImportsMapping {
    pub fn add(&mut self, name: String, module_str: String) {
        self.imports.insert(name, module_str);
    }

    pub fn new() -> Self {
        Self {
            imports: HashMap::new()
        }
    }
}

