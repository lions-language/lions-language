use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RefPtr{
    ptr: usize,
    typ: u8
}

pub type Heap<T> = Box<T>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeapPtr {
    ptr: usize,
    typ: u8
}

mod ref_ptr;
mod heap_ptr;

