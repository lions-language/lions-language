use crate::function::{FunctionControl};
use libtype::{Type, TypeValue, PackageType, PackageTypeValue};
use libtype::function::{FunctionControlInterface, Function};
use libtype::function::{FindFunctionContext, FindFunctionResult
                        , AddFunctionContext, AddFunctionResult};
use libhosttype::primeval::PrimevalControl;
use libhostfunction::control::PrimevalFuncControl;

impl FunctionControl {
    pub fn find_function(&mut self, context: &FindFunctionContext) -> FindFunctionResult {
        self.find_instance(&context.typ, &context.package_typ).find_function(context)
    }

    pub fn add_function(&mut self, context: AddFunctionContext,
        func: Function) -> AddFunctionResult {
        self.find_instance(&context.typ, &context.package_typ).add_function(context, func)
    }

    /*
     * 为了代码的可维护性, 将损失一些运行时开销 (但是牺牲的性能很少, 因为实例很少)
     * 因为无法在编译期确定返回类型, 所以 使用 dyn 获取实例对象 (运行时计算类型, 编译期预留指针空间)
     * */
    fn find_instance(&mut self, typ: &Option<&Type>
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
                    PackageTypeValue::Primeval => {
                        &mut self.primeval_func_control
                    },
                    PackageTypeValue::Current => {
                        unimplemented!();
                    }
                }
            }
        }
    }

    pub fn new() -> Self {
        Self {
            primeval_control: PrimevalControl::new(),
            primeval_func_control: PrimevalFuncControl::new()
        }
    }
}

