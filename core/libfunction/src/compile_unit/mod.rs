use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess
    , FindFunctionHandle};
use libcommon::ptr::RefPtr;

pub struct Handler {
    container: hashmap::Container
}

impl Handler {
    pub fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        self.container.is_exists(&context.module_str, &context.func_str)
    }

    pub fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        match self.container.find(&context.module_str, &context.func_str, handle) {
            Some(f) => {
                FindFunctionResult::Success(FindFuncSuccess::new(f))
            },
            None => {
                FindFunctionResult::NotFound
            }
        }
    }

    pub fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        if context.is_overload.clone() {
            self.container.add(context.module_str, context.func_str, handle, func);
        } else {
            self.container.add(context.module_str, context.func_name, handle, func);
        }
        AddFunctionResult::Success
    }

    pub fn new() -> Self {
        Self {
            container: hashmap::Container::new()
        }
    }
}

mod hashmap;
