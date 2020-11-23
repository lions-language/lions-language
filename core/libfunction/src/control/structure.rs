use libtype::function::{FunctionControlInterface
    , FindFunctionContext, AddFunctionContext
    , FindFunctionResult, AddFunctionResult
    , Function, FindFuncSuccess
    , FindFunctionHandle};
use libtype::{Type, PackageTypeValue
    , TypeValue};
use libtype::package::{PackageStr};
use libcommon::ptr::{RefPtr};
use crate::compile_unit;
use super::{StructFunctionControl};
use std::collections::{HashMap};

impl FunctionControlInterface for StructFunctionControl {
    fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        let ps = &context.package_str;
        match ps {
            PackageStr::Itself => {
                match self.handler(self.typ_from_find_unchecked(context)) {
                    Some(h) => {
                        h.is_exists(context)
                    },
                    None => {
                        (false, FindFunctionHandle::new_null())
                    }
                }
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        let ps = &context.package_str;
        match ps {
            PackageStr::Itself => {
                match self.handler(self.typ_from_find_unchecked(context)) {
                    Some(h) => {
                        h.find_function(context, handle)
                    },
                    None => {
                        FindFunctionResult::NotFound
                    }
                }
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        let ps = &context.package_str;
        match ps {
            PackageStr::Itself => {
                // println!("{:?}", func);
                self.handler_mut(self.typ_from_add_unchecked(&context))
                    .as_mut::<compile_unit::Handler>().add_function(context, handle, func)
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

    fn handler(&self, typ: &Type) -> Option<&compile_unit::Handler> {
        match typ.typ_ref() {
            TypeValue::Structure(s) => {
                match self.handlers.get(s.struct_obj_ref()) {
                    Some(h) => {
                        Some(h)
                    },
                    None => {
                        None
                    }
                }
            },
            _ => {
                panic!("expect struct, but found: {:?}", typ.typ_ref());
            }
        }
    }

    fn handler_mut(&mut self, typ: &Type) -> RefPtr {
        /*
         * 如果 StructObject 不存在于 map 中, 需要先添加 StructObject
         * */
        match typ.typ_ref() {
            TypeValue::Structure(s) => {
                match self.handlers.get_mut(s.struct_obj_ref()){
                    Some(h) => {
                        RefPtr::from_ref(h)
                    },
                    None => {
                        self.handlers.insert(s.struct_obj_clone()
                            , compile_unit::Handler::new());
                        /*
                         * NOTE
                         *  不能直接返回 &compile_unit::Handler
                         *  会存在多个可变引用的借用检查器错误
                         * */
                        RefPtr::from_ref(
                            self.handlers.get_mut(s.struct_obj_ref()).expect("should not happend"))
                    }
                }
            },
            _ => {
                panic!("expect struct, but found: {:?}", typ.typ_ref());
            }
        }
    }

    pub fn new() -> Self {
        Self {
            handlers: HashMap::new()
        }
    }
}
