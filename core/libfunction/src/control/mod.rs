use libtype::{StructObject};
use crate::compile_unit;
use std::collections::{HashMap};

/*
 * 无类型函数
 * */
pub struct NotypeFunctionControl {
    compile_unit_handler: compile_unit::Handler
}

/*
 * 结构体方法
 * */
pub struct StructFunctionControl {
    handlers: HashMap<StructObject, compile_unit::Handler>
}

mod notype;
mod structure;
