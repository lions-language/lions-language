use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess
    , FindFunctionHandle};
use libtype::PackageTypeValue;
use crate::compile_unit;

/*
 * 存储编译单元中的函数声明
 * */
pub struct NotypeFunctionControl {
    compile_unit_handler: compile_unit::Handler
}

impl FunctionControlInterface for NotypeFunctionControl {
    fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        unimplemented!();
    }

    fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        let pt = context.package_typ.expect("must be specify package type");
        match pt.typ_ref() {
            PackageTypeValue::Crate => {
                self.compile_unit_handler.find_function(context, handle)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        unimplemented!();
    }
}

impl NotypeFunctionControl {
    pub fn new() -> Self {
        Self {
            compile_unit_handler: compile_unit::Handler::new()
        }
    }
}
