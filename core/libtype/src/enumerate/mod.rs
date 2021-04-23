use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use crate::{Type, TypeAttrubute
    , AddressType};
use crate::function::{FunctionParam, FunctionReturn};
use std::collections::{HashMap};

#[derive(Debug, FieldGet
    , FieldGetMove, NewWithAll
    , Default, PartialEq, Eq)]
pub struct EnumerateItem {
    name: String,
    typ: Option<Type>
}

#[derive(Debug, FieldGet
    , FieldGetMove, NewWithAll
    , Default, PartialEq, Eq)]
pub struct EnumerateDefine {
    name: String,
    items: Option<Vec<EnumerateItem>>
}

