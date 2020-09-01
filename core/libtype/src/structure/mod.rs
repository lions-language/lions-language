use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use std::collections::{HashMap};

#[derive(Debug, FieldGet
    , FieldGetMove)]
pub struct StructMethod {
}

#[derive(Debug, FieldGet
    , FieldGetMove)]
pub struct StructField {
    index: usize
}

#[derive(Debug, FieldGet
    , FieldGetMove)]
pub struct StructMember {
    index: usize,
    order: Vec<String>,
    members: HashMap<String, StructField>
}

#[derive(Debug, FieldGet
    , FieldGetMove)]
pub struct StructDefine {
    name: String,
    member: StructMember
}

#[derive(Debug, Clone)]
pub struct StructureData {
}

mod member;

