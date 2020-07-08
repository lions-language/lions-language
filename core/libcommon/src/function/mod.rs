use std::cmp::Eq;
use std::hash::Hash;

#[derive(Eq, PartialEq, Hash)]
pub struct FunctionKey(String);

impl FunctionKey {
    pub fn key_ref(&self) -> &str {
        &self.0
    }

    pub fn new(v: String) -> Self {
        Self(v)
    }
}

