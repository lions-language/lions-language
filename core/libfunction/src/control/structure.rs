use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess
    , FindFunctionHandle};
use libtype::{Type, PackageTypeValue};
use crate::compile_unit;
use super::{StructFunctionControl};
use std::collections::{HashMap};

impl FunctionControlInterface for StructFunctionControl {
    fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        let pt = context.package_typ.expect("must be specify package type");
        match pt.typ_ref() {
            PackageTypeValue::Crate => {
                self.handler(self.typ_from_find_unchecked(context)).is_exists(context)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        let pt = context.package_typ.expect("must be specify package type");
        match pt.typ_ref() {
            PackageTypeValue::Crate => {
                self.handler(self.typ_from_find_unchecked(context)).find_function(context, handle)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        let pt = context.package_typ.expect("must be specify package type");
        match pt.typ_ref() {
            PackageTypeValue::Crate => {
                self.handler_mut(self.typ_from_add_unchecked(&context)).add_function(context, handle, func)
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl StructFunctionControl {
    fn typ_from_add_unchecked<'a>(&self, context: &'a AddFunctionContext) -> &'a Type {
        context.typ.as_ref().expect("struct must be type")
    }

    fn typ_from_find_unchecked<'a>(&self, context: &'a FindFunctionContext) -> &'a Type {
        context.typ.as_ref().expect("struct must be type")
    }

    fn handler(&self, typ: &Type) -> &compile_unit::Handler {
        unimplemented!();
    }

    fn handler_mut(&mut self, typ: &Type) -> &mut compile_unit::Handler {
        unimplemented!();
    }

    pub fn new() -> Self {
        Self {
            handlers: HashMap::new()
        }
    }
}
