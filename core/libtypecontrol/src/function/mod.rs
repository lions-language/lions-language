use libhosttype::primeval::{PrimevalControl};
use libhostfunction::control::{PrimevalFuncControl};
use libfunction::control::{NotypeFunctionControl};

pub struct FunctionControl {
    primeval_control: PrimevalControl,
    primeval_func_control: PrimevalFuncControl,
    function_control: NotypeFunctionControl
}

mod function_control;
