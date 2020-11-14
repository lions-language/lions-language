use std::collections::HashMap;

pub struct ImportsMapping {
    imports: HashMap<String, String>
}

impl ImportsMapping {
    pub fn add(&mut self, name: String, module_str: String) {
        self.imports.insert(name, module_str);
    }

    pub fn exists(&mut self, name: &str) -> bool {
        self.imports.contains_key(name)
    }

    pub fn get_clone(&mut self, name: &str) -> Option<String> {
        match self.imports.get(name) {
            Some(v) => {
                Some(v.to_string())
            },
            None => {
                None
            }
        }
    }

    pub fn new() -> Self {
        Self {
            imports: HashMap::new()
        }
    }
}

