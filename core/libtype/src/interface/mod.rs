use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use crate::{Type, TypeAttrubute
    , AddressType};
use std::collections::{HashMap};

#[derive(Debug, FieldGet
    , FieldGetMove, NewWithAll
    , Default)]
pub struct InterfaceDefine {
    name: String
}

