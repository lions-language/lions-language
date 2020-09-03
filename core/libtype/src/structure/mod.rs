use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use std::collections::{HashMap};

#[derive(Debug, FieldGet
    , FieldGetMove)]
pub struct StructMethod {
}

#[derive(Debug, FieldGet
    , FieldGetMove, Clone
    , Default)]
pub struct StructField {
    index: usize
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

