use super::PackageIndex;
use std::collections::HashMap;

impl PackageIndex {
    pub fn get_index(&mut self, package_str: &str) -> usize {
        match self.indexs.get(package_str) {
            Some(idx) => {
                *idx
            },
            None => {
                let idx = self.index + 1;
                self.indexs.insert(package_str.to_string(), idx);
                idx
            }
        }
    }

    pub fn new() -> Self {
        Self {
            indexs: HashMap::new(),
            index: 0
        }
    }
}
