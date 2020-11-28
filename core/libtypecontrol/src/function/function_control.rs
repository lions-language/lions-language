use crate::function::{FunctionControl};
use libtype::{Type, TypeValue};
use libtype::function::{FunctionControlInterface, Function};
use libtype::function::{FindFunctionContext, FindFunctionResult
                        , AddFunctionContext, AddFunctionResult
                        , FindFunctionHandle};
use libtype::package::{PackageStr};
use libhosttype::primeval::PrimevalControl;
use libhostfunction::control::PrimevalFuncControl;
use libfunction::control::{NotypeFunctionControl, StructFunctionControl};

impl FunctionControl {
    pub fn is_exists(&mut self, context: &FindFunctionContext) -> (bool, FindFunctionHandle) {
        self.find_instance_find(&context.typ, &context.package_str
            , context).is_exists(context)
    }

    pub fn find_function<'a>(&'a mut self, context: &'a FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult {
        self.find_instance_find(&context.typ, &context.package_str
            , context).find_function(context, handle)
    }

    pub fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult {
        self.find_instance_add(&context.typ.as_ref(), &context.package_str)
            .add_function(context, handle, func)
    }

    /*
     * 为了代码的可维护性, 将损失一些运行时开销 (但是牺牲的性能很少, 因为实例很少)
     * 因为无法在编译期确定返回类型, 所以 使用 dyn 获取实例对象 (运行时计算类型, 编译期预留指针空间)
     * */
    fn find_instance_find<'a>(&'a mut self, typ: &Option<&Type>
        , package_str: &'a PackageStr
        , find_context: &FindFunctionContext) -> &'a dyn FunctionControlInterface {
        match typ {
            Some(ty) => {
                match ty.typ_ref() {
                    TypeValue::Primeval(_) => {
                        &mut self.primeval_control
                    },
                    _ => {
                        &mut self.struct_function_control
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
                    match package_str {
                        PackageStr::Itself => {
                            &mut self.notype_function_control
                        },
                        PackageStr::Third(pbp) => {
                            /*
                             * 如果是第三方包中的方法, 从第三方包中查找函数
                             * */
                            &pbp.function_control.as_ref::<FunctionControl>().notype_function_control
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
        , package_str: &PackageStr) -> &mut dyn FunctionControlInterface {
        match typ {
            Some(ty) => {
                match ty.typ_ref() {
                    TypeValue::Primeval(_) => {
                        &mut self.primeval_control
                    },
                    _ => {
                        &mut self.struct_function_control
                    }
                }
            },
            None => {
                /*
                 * 全局函数 (不属于任何类型)
                 *  1. 先判断是否是内置的函数 call primeval control
                 * */
                match package_str {
                    PackageStr::Itself => {
                        &mut self.notype_function_control
                    },
                    _ => {
                        unimplemented!("{:?}", package_str);
                    }
                }
            }
        }
    }

    pub fn new() -> Self {
        Self {
            primeval_control: PrimevalControl::new(),
            primeval_func_control: PrimevalFuncControl::new(),
            notype_function_control: NotypeFunctionControl::new(),
            struct_function_control: StructFunctionControl::new()
        }
    }
}

