use crate::function::{FunctionControl};
use libtype::{Type, TypeValue, PackageType, PackageTypeValue};
use libtype::function::{FunctionControlInterface, Function};
use libtype::function::{FindFunctionContext, FindFunctionResult
                        , AddFunctionContext, AddFunctionResult
                        , FindFunctionHandle};
use libhosttype::primeval::PrimevalControl;
use libhostfunction::control::PrimevalFuncControl;
use libfunction::control::NotypeFunctionControl;

impl FunctionControl {
    pub fn is_exists(&mut self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        self.find_instance_find(&context.typ, &context.package_typ
            , context).is_exists(context)
    }

    pub fn find_function<'a>(&'a mut self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        self.find_instance_find(&context.typ, &context.package_typ
            , context).find_function(context, handle)
    }

    pub fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        self.find_instance_add(&context.typ, &context.package_typ).add_function(context, handle, func)
    }

    /*
     * 为了代码的可维护性, 将损失一些运行时开销 (但是牺牲的性能很少, 因为实例很少)
     * 因为无法在编译期确定返回类型, 所以 使用 dyn 获取实例对象 (运行时计算类型, 编译期预留指针空间)
     * */
    fn find_instance_find(&mut self, typ: &Option<&Type>
        , package_typ: &Option<&PackageType>
        , find_context: &FindFunctionContext) -> &mut dyn FunctionControlInterface {
        match typ {
            Some(ty) => {
                match ty.typ_ref() {
                    TypeValue::Primeval(_) => {
                        &mut self.primeval_control
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            },
            None => {
                /*
                 * 全局函数 (不属于任何类型)
                 *  1. 先判断是否是内置的函数 call primeval control
                 * */
                let (is_exists, _) = self.primeval_func_control.is_exists(find_context);
                if is_exists {
                    &mut self.primeval_func_control
                } else {
                    let package_typ = package_typ.expect("must be specify package type");
                    match package_typ.typ_ref() {
                        PackageTypeValue::Crate => {
                            &mut self.function_control
                        },
                        _ => {
                            unimplemented!();
                        }
                    }
                }
            }
        }
    }

    fn find_instance_add(&mut self, typ: &Option<&Type>
        , package_typ: &Option<&PackageType>) -> &mut dyn FunctionControlInterface {
        match typ {
            Some(ty) => {
                match ty.typ_ref() {
                    TypeValue::Primeval(_) => {
                        &mut self.primeval_control
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            },
            None => {
                /*
                 * 全局函数 (不属于任何类型)
                 *  1. 先判断是否是内置的函数 call primeval control
                 * */
                let package_typ = package_typ.expect("must be specify package type");
                match package_typ.typ_ref() {
                    PackageTypeValue::Crate => {
                        &mut self.function_control
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            }
        }
    }

    pub fn new() -> Self {
        Self {
            primeval_control: PrimevalControl::new(),
            primeval_func_control: PrimevalFuncControl::new(),
            function_control: NotypeFunctionControl::new()
        }
    }
}

