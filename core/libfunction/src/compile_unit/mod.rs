use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess};

pub struct Container {
}

impl Container {
    pub fn find_function(&self, context: &FindFunctionContext) -> FindFunctionResult {
        unimplemented!();
    }

    pub fn add_function(&mut self, context: AddFunctionContext
        , func: Function) -> AddFunctionResult {
        unimplemented!();
    }

    pub fn new() -> Self {
        Self {
        }
    }
}

mod hashmap;
