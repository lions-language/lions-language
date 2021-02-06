use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use crate::{Type, TypeAttrubute
    , AddressType};
use crate::function::{FunctionParam, FunctionReturn};
use std::collections::{HashMap};

#[derive(Debug, FieldGet
    , FieldGetMove, NewWithAll
    , Default)]
pub struct InterfaceFunctionStatement {
    func_param: Option<Vec<FunctionParam>>,
    func_return: Option<FunctionReturn>
}

#[derive(Debug, FieldGet
    , FieldGetMove, NewWithAll
    , Default)]
pub struct InterfaceDefine {
    name: String,
    function_statement: Option<Vec<InterfaceFunctionStatement>>
}

