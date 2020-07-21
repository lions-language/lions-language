use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetClone};
use crate::primeval::PrimevalType;
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Debug)]
pub struct StructObject {
    pub name: String
}

impl StructObject {
    pub fn name_str(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct Structure {
    /*
     * 因为每一个结构的类型信息在整个系统中只有一份, 所以这里将结构的内存指针存储下来
     * 之后获取类型 string 的时候, 就只要访问地址中的字符串就可以, 降低内存消耗, 提高效率
     *
     * 在构造 结构类型时, 会从 struct_control 中找到 StructObject 指针
     *  比如: let a = mod1::Test{};
     *  compile 阶段会通过 mod1 从 struct_control 中找到 StructObject 指针, 然后通过这个指针, 构造
     *  Type对象, 调用 function_control 获取方法定义
     * */
    struct_obj_ptr: RefPtr
}

impl Structure {
    pub fn new(struct_obj_ptr: RefPtr) -> Self {
        Self {
            struct_obj_ptr: struct_obj_ptr
        }
    }
}

#[derive(Debug)]
pub enum BoolType {
    True,
    False
}

#[derive(Debug, Clone)]
pub enum TypeAttrubute {
    // Replicate,
    Move,
    Pointer,
    Ref,
}

impl TypeAttrubute {
    pub fn to_str(&self) -> &'static str {
        match self {
            TypeAttrubute::Move => {
                ""
            },
            TypeAttrubute::Ref => {
                "&"
            },
            TypeAttrubute::Pointer => {
                "*"
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Primeval {
    pub typ: PrimevalType
}

impl Primeval {
    pub fn new(typ: PrimevalType) -> Self {
        Self{
            typ: typ
        }
    }
}

#[derive(Debug, Clone)]
pub enum TypeValue {
    /*
     * 原生类型
     * */
    Primeval(Primeval),
    /*
     * 结构体类型
     * */
    Structure(Structure),
    /*
     * 空类型
     * */
    Empty
}

#[derive(Debug, Clone, FieldGet, FieldGetClone)]
pub struct Type {
    typ: TypeValue,
    attr: TypeAttrubute
}

impl Type {
    pub fn new(typ: TypeValue, attr: TypeAttrubute) -> Self {
        Self {
            typ: typ,
            attr: attr
        }
    }
}

impl Default for Type {
    fn default() -> Self {
        Type::new(TypeValue::Empty, TypeAttrubute::Move)
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq, Default)]
pub struct AddressKey {
    pub module_index: u64,
    pub index: u64
}

impl AddressKey {
    pub fn new(module_index: u64, index: u64) -> Self {
        Self {
            module_index: module_index,
            index: index
        }
    }   
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum AddressType {
    Static,
    Stack,
}

impl Default for AddressType {
    fn default() -> Self {
        AddressType::Stack
    }
}

#[derive(Debug, Clone, Default, PartialEq, Hash, Eq, FieldGet, FieldGetClone)]
pub struct AddressValue {
    typ: AddressType,
    addr: AddressKey
}

impl AddressValue {
    pub fn new(typ: AddressType, addr: AddressKey) -> Self {
        Self {
            typ: typ,
            addr: addr
        }
    }
}

pub mod function;
pub mod primeval;
pub mod typ;
pub mod module;
pub mod instruction;

