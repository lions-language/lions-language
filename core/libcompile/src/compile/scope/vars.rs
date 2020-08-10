use libmacro::{FieldGet, NewWithAll};
use libtype::{Type};
use crate::address::Address;
use std::collections::HashMap;

#[derive(FieldGet, NewWithAll)]
pub struct Variant {
    addr: Address,
    typ: Type
}

pub struct Variants {
    vars: HashMap<String, Variant>
}

impl Variants {
    pub fn add(&mut self, name: String, var: Variant) {
        self.vars.insert(name.clone(), var);
        // let (k, _) = self.vars.get_key_value(&name).expect("should not happend");
        // k
    }

    pub fn remove(&mut self, name: &String) {
        self.vars.remove(name);
    }

    pub fn get(&self, name: &str) -> Option<&Variant> {
        self.vars.get(name)
    }

    pub fn get_with_key(&self, name: &str) -> Option<(&String, &Variant)> {
        self.vars.get_key_value(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Variant> {
        self.vars.get_mut(name)
    }

    pub fn len(&self) -> usize {
        self.vars.len()
    }

    pub fn new() -> Self {
        Self {
            vars: HashMap::new()
        }
    }
}
