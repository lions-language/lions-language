use libmacro::{FieldGet};
use number::int8::{Int8};
use number::int16::{Int16};
use number::int32::{Int32};
use number::int64::{Int64};
use number::uint8::{Uint8};
use number::uint16::{Uint16};
use number::uint32::{Uint32};
use number::uint64::{Uint64};
use number::float32::{Float32};
use number::float64::{Float64};
use string::{Str};
use crate::{AddressValue};
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimevalType {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Str
}

#[derive(Debug, Clone, FieldGet)]
pub struct StrSlice {
    addr_value: AddressValue,
    start: usize,
    end: usize
}

#[derive(Debug, Clone)]
pub enum PrimevalData {
    Uint8(Option<Uint8>),
    Uint16(Option<Uint16>),
    Uint32(Option<Uint32>),
    Uint64(Option<Uint64>),
    Int8(Option<Int8>),
    Int16(Option<Int16>),
    Int32(Option<Int32>),
    Int64(Option<Int64>),
    Float32(Option<Float32>),
    Float64(Option<Float64>),
    Str(Option<Str>),
    /*
     * 自身没有存储数据, 只是存储了字符串中的位置信息
     * */
    StrSlice(StrSlice),
}

pub mod number;
pub mod string;
pub mod primeval_type;

