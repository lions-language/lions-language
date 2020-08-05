use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove};
use crate::primeval::{PrimevalType, PrimevalData};
use crate::structure::{StructureData};
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    Empty
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
            },
            TypeAttrubute::Empty => {
                "()"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    Any,
    Empty
}

impl TypeValue {
    pub fn is_any(&self) -> bool {
        match self {
            TypeValue::Any => {
                true
            },
            _ => {
                false
            }
        }
    }
}

/*
 * 类型存储在栈上还是堆上
 * */
#[derive(Debug, Clone)]
pub enum TypeAddrType {
    Stack,
    Heap
}

#[derive(Debug, Clone, FieldGet, FieldGetClone)]
pub struct Type {
    typ: TypeValue,
    attr: TypeAttrubute,
    addr_typ: TypeAddrType
}

#[derive(Debug, Clone)]
pub enum DataValue {
    Primeval(PrimevalData),
    Structure(StructureData),
    Empty
}

#[derive(Debug, Clone, FieldGet)]
pub struct Data {
    value: DataValue
}

impl Data {
    pub fn new_empty() -> Self {
        Self {
            value: DataValue::Empty
        }
    }

    pub fn new(value: DataValue) -> Self {
        Self {
            value: value
        }
    }
}

#[derive(Debug, Clone)]
pub enum PackageTypeValue {
    Crate,
    Unknown
}

#[derive(Debug, Clone, FieldGet, FieldGetClone)]
pub struct PackageType {
    typ: PackageTypeValue
}

impl PackageType {
    pub fn new(typ: PackageTypeValue) -> Self {
        Self {
            typ: typ
        }
    }
}

impl Type {
    /*
     * 创建 非 堆 类型
     * */
    pub fn new(typ: TypeValue, attr: TypeAttrubute) -> Self {
        Type::_new(typ, attr, TypeAddrType::Stack)
    }

    pub fn new_without_attr(typ: TypeValue) -> Self {
        Type::new(typ, TypeAttrubute::Empty)
    }

    pub fn new_heap(typ: TypeValue, attr: TypeAttrubute) -> Self {
        Type::_new(typ, attr, TypeAddrType::Heap)
    }

    pub fn set_type_attribute(&mut self, attr: TypeAttrubute) {
        *&mut self.attr = attr;
    }

    pub fn to_address_type(&self) -> AddressType {
        match &self.addr_typ {
            TypeAddrType::Stack => {
                AddressType::Stack
            },
            TypeAddrType::Heap => {
                AddressType::Heap
            }
        }
    }

    fn _new(typ: TypeValue, attr: TypeAttrubute, addr_typ: TypeAddrType) -> Self {
        Self {
            typ: typ,
            attr: attr,
            addr_typ: addr_typ
        }
    }
}

impl Default for Type {
    fn default() -> Self {
        Type::new(TypeValue::Empty, TypeAttrubute::Move)
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq, Default, FieldGet, FieldGetClone)]
pub struct AddressKey {
    pub index: u64
}

impl AddressKey {
    pub fn new(index: u64) -> Self {
        Self {
            index: index
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum AddressType {
    Static,
    Stack,
    Heap,
    Invalid
}

impl Default for AddressType {
    fn default() -> Self {
        AddressType::Invalid
    }
}

#[derive(Debug, Clone, Default, PartialEq
    , Hash, Eq, FieldGet, FieldGetClone
    , FieldGetMove)]
pub struct AddressValue {
    typ: AddressType,
    addr: AddressKey
}

impl AddressValue {
    pub fn is_invalid(&self) -> bool {
        if let AddressType::Invalid = self.typ_ref() {
            return true;
        };
        false
    }

    pub fn new_invalid() -> Self {
        Self::default()
    }

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
pub mod package;
pub mod structure;

