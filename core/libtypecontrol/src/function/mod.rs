use libhosttype::primeval::{PrimevalControl};
use libhostfunction::control::{PrimevalFuncControl};
use libfunction::control::{NotypeFunctionControl};
use libfunction::control::{StructFunctionControl};

pub struct FunctionControl {
    primeval_control: PrimevalControl,
    primeval_func_control: PrimevalFuncControl,
    notype_function_control: NotypeFunctionControl,
    struct_function_control: StructFunctionControl
}

mod function_control;
