use std::cmp::Eq;
use std::hash::Hash;

#[derive(Eq, PartialEq, Hash)]
pub struct ModuleKey {
    name: String
}

impl ModuleKey {
    pub fn new(name: String) -> Self {
        Self {
            name: name
        }
    }
}

pub struct Module {
    pub key: ModuleKey
}

