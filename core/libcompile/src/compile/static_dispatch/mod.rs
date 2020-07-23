use libtype::AddressKey;
use crate::compile::CompileType;

struct Data {
}

pub trait StaticAlloc {
    fn alloc(&mut self, data: Data) -> AddressKey;
}

pub struct Dispatch {
    env: CompileType
}

impl Dispatch {
    pub fn switch_env(&mut self, env: CompileType) {
        *(&mut self.env) = env;
    }

    pub fn alloc(&mut self, data: Data) -> AddressKey {
        unimplemented!();
    }

    pub fn new(env: CompileType) -> Self {
        Self {
            env: env
        }
    }
}

mod runtime;
mod compile;
