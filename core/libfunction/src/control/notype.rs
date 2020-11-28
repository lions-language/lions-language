use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess
    , FindFunctionHandle};
use libtype::package::{PackageStr};
use crate::compile_unit;
use super::{NotypeFunctionControl};

impl FunctionControlInterface for NotypeFunctionControl {
    fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        self.compile_unit_handler.is_exists(context)
        /*
        let ps = &context.package_str;
        match ps {
            PackageStr::Itself => {
                self.compile_unit_handler.is_exists(context)
            },
            _ => {
                unimplemented!();
            }
        }
        */
    }

    fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        self.compile_unit_handler.find_function(context, handle)
        /*
        let ps = &context.package_str;
        match ps {
            PackageStr::Itself => {
                self.compile_unit_handler.find_function(context, handle)
            },
            _ => {
                unimplemented!();
            }
        }
        */
    }

    fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        let ps = &context.package_str;
        match ps {
            PackageStr::Itself => {
                self.compile_unit_handler.add_function(context, handle, func)
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl NotypeFunctionControl {
    pub fn new() -> Self {
        Self {
            compile_unit_handler: compile_unit::Handler::new()
        }
    }
}
