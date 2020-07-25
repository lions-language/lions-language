use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess
    , FindFunctionHandle};
use crate::define;

pub struct PrimevalFuncControl {
}

impl FunctionControlInterface for PrimevalFuncControl {
    fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        match define::get_method(context.func_str) {
            Some(f) => {
                (true, FindFunctionHandle::from_ref::<Function>(f))
            },
            None => {
                (false, FindFunctionHandle::new_null())
            }
        }
    }

    fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        match handle {
            Some(h) => {
                if h.is_null() {
                    FindFunctionResult::NotFound
                } else {
                    FindFunctionResult::Success(FindFuncSuccess::new(
                            h.as_ref::<Function>()))
                }
            },
            None => {
                match define::get_method(context.func_str) {
                    Some(f) => {
                        FindFunctionResult::Success(FindFuncSuccess::new(f))
                    },
                    None => {
                        FindFunctionResult::NotFound
                    }
                }
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        panic!("should not happend");
    }
}

impl PrimevalFuncControl {
    pub fn new() -> Self {
        Self {
        }
    }
}
