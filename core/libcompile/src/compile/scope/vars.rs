use libmacro::{NewWithAll};
use crate::address::Address;
use std::collections::HashMap;

#[derive(NewWithAll)]
pub struct Variant {
    addr: Address
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

    pub fn new() -> Self {
        Self {
            vars: HashMap::new()
        }
    }
}
