use libmacro::{FieldGet, FieldGetMove, NewWithAll};
use libtype::package::{PackageStr};
use std::collections::HashMap;

#[derive(FieldGet, FieldGetMove, NewWithAll, Clone)]
pub struct ImportItem {
    module_str: String,
    package_str: PackageStr
}

pub struct ImportsMapping {
    imports: HashMap<String, ImportItem>
}

impl ImportsMapping {
    pub fn add(&mut self, name: String, item: ImportItem) {
        self.imports.insert(name, item);
    }

    pub fn exists(&mut self, name: &str) -> bool {
        self.imports.contains_key(name)
    }

    pub fn get_clone(&mut self, name: &str) -> Option<ImportItem> {
        match self.imports.get(name) {
            Some(v) => {
                Some(v.clone())
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

