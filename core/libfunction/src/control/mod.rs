use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess};
use libtype::PackageTypeValue;
use crate::compile_unit;

/*
 * 存储编译单元中的函数声明
 * */
pub struct NotypeFunctionControl {
    compile_unit_handler: compile_unit::Container
}

impl FunctionControlInterface for NotypeFunctionControl {
    fn find_function(&self, context: &FindFunctionContext) -> FindFunctionResult {
        let pt = context.package_typ.expect("must be specify package type");
        match pt.typ_ref() {
            PackageTypeValue::Crate => {
                self.compile_unit_handler.find_function(context)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , func: Function) -> AddFunctionResult {
        unimplemented!();
    }
}

impl NotypeFunctionControl {
    pub fn new() -> Self {
        Self {
            compile_unit_handler: compile_unit::Container::new()
        }
    }
}
