use crate::function::{FunctionControl};
use libtype::{Type, TypeValue};
use libtype::function::{FunctionControlInterface, Function};
use libtype::function::{FindFunctionContext, FindFunctionResult
                        , AddFunctionContext, AddFunctionResult};
use libhosttype::primeval::PrimevalControl;

impl FunctionControl {
    pub fn find_function(&mut self, context: &FindFunctionContext) -> FindFunctionResult {
        self.find_instance(context.typ).find_function(context)
    }

    pub fn add_function(&mut self, context: AddFunctionContext,
        func: Function) -> AddFunctionResult {
        self.find_instance(context.typ).add_function(context, func)
    }

    /*
     * 为了代码的可维护性, 将损失一些运行时开销 (但是牺牲的性能很少, 因为实例很少)
     * 因为无法在编译期确定返回类型, 所以 使用 dyn 获取实例对象 (运行时计算类型, 编译期预留指针空间)
     * */
    fn find_instance(&mut self, typ: &Type) -> &mut dyn FunctionControlInterface {
        match typ.typ_ref() {
            TypeValue::Primeval(_) => {
                &mut self.primeval_control
            },
            _ => {
                unimplemented!();
            }
        }
    }

    pub fn new() -> Self {
        Self {
            primeval_control: PrimevalControl::new()
        }
    }
}

