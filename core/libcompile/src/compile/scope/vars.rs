use libmacro::{FieldGet, FieldGetMove, NewWithAll};
use libtype::{Type, TypeAttrubute, AddressKey};
use crate::address::Address;
use std::collections::{HashMap, HashSet};

#[derive(FieldGet, FieldGetMove)]
pub struct Variant {
    addr: Address,
    typ: Type,
    typ_attr: TypeAttrubute,
    /*
     * 连续地址
     * */
    consecutive_addr: Option<HashSet<AddressKey>>
}

impl Variant {
    pub fn new(addr: Address, typ: Type, typ_attr: TypeAttrubute) -> Self {
        let length = addr.addr_ref().addr_ref().length_clone();
        let consecutive_addr = if length == 0 {
            None
        } else {
            let mut s = HashSet::with_capacity(length);
            for i in 1..=length {
                s.insert(addr.addr_ref().addr_ref().clone_with_index_plus(i));
            }
            Some(s)
        };
        Self {
            addr: addr,
            typ: typ,
            typ_attr: typ_attr,
            consecutive_addr: consecutive_addr
        }
    }
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
