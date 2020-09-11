use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use crate::{Type, TypeAttrubute
    , AddressType};
use std::collections::{HashMap};

#[derive(Debug, FieldGet
    , FieldGetMove)]
pub struct StructMethod {
}

#[derive(Debug, FieldGet, FieldGetClone
    , FieldGetMove, Clone
    , Default)]
pub struct StructField {
    index: usize,
    typ: Type,
    typ_attr: TypeAttrubute,
    addr_type: AddressType
}

#[derive(Debug, FieldGet
    , FieldGetMove
    , Default)]
pub struct StructMember {
    index: usize,
    members: HashMap<String, StructField>
}

#[derive(Debug, FieldGet
    , FieldGetMove, NewWithAll
    , Default)]
pub struct StructDefine {
    name: String,
    member: Option<StructMember>
}

#[derive(Debug, Clone)]
pub struct StructureData {
}

mod member;
mod field;
mod define;
mod data;

