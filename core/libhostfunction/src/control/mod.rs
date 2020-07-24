use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess};
use crate::define;

pub struct PrimevalFuncControl {
}

impl FunctionControlInterface for PrimevalFuncControl {
    fn find_function(&self, context: &FindFunctionContext) -> FindFunctionResult {
        match define::get_method(context.func_str) {
            Some(f) => {
                FindFunctionResult::Success(FindFuncSuccess::new(f))
            },
            None => {
                FindFunctionResult::NotFound
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , func: Function) -> AddFunctionResult {
        unimplemented!();
    }
}

impl PrimevalFuncControl {
    pub fn new() -> Self {
        Self {
        }
    }
}
