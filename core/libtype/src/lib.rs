use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use crate::primeval::{PrimevalType, PrimevalData};
use crate::structure::{StructureData, StructDefine};
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructObject(RefPtr);

impl StructObject {
    pub fn from_ref(define: &StructDefine) -> Self {
        Self(RefPtr::from_ref::<StructDefine>(define))
    }
    pub fn as_ref(&self) -> &StructDefine {
        self.0.as_ref::<StructDefine>()
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
    struct_obj: StructObject
}

impl Structure {
    pub fn new(struct_obj: StructObject) -> Self {
        Self {
            struct_obj: struct_obj
        }
    }
}

#[derive(Debug)]
pub enum BoolType {
    True,
    False
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeAttrubute {
    // Replicate,
    Move,
    Pointer,
    Ref,
    /*
     * 函数内部创建的对象, 最终会到外层作用域
     * 但是属性不是Move, 是一个引用, 之后就可以调用 &create 作为参数的方法了
     * */
    CreateRef,
    MutRef,
    Empty
}

impl TypeAttrubute {
    pub fn is_ref(&self) -> bool {
        match self {
            TypeAttrubute::Ref
            | TypeAttrubute::MutRef => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn is_move(&self) -> bool {
        match self {
            TypeAttrubute::Move
            | TypeAttrubute::CreateRef => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn is_ref_as_param(&self) -> bool {
        /*
         * 作为参数是否是引用的
         * */
        match self {
            TypeAttrubute::Ref
            | TypeAttrubute::MutRef
            | TypeAttrubute::CreateRef => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn is_ref_as_return(&self) -> bool {
        match self {
            TypeAttrubute::Ref
            | TypeAttrubute::MutRef => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn is_move_as_param(&self) -> bool {
        match self {
            TypeAttrubute::Move => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn is_move_as_return(&self) -> bool {
        match self {
            TypeAttrubute::Move
            | TypeAttrubute::CreateRef => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            TypeAttrubute::Move => {
                ""
            },
            TypeAttrubute::Ref => {
                "&"
            },
            TypeAttrubute::CreateRef => {
                "&create "
            },
            TypeAttrubute::MutRef => {
                "&mut "
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

impl Default for TypeAttrubute {
    fn default() -> Self {
        TypeAttrubute::Move
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
    Any,
    /*
     * 空类型
     * */
    Empty,
    /*
     * null 类型
     * */
    Null
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

impl Default for PackageTypeValue {
    fn default() -> Self {
        PackageTypeValue::Unknown
    }
}

#[derive(Debug, Clone, Default, FieldGet, FieldGetClone)]
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

    pub fn new_with_addrtyp(typ: TypeValue
        , addr_typ: TypeAddrType) -> Self {
        Type::_new(typ, TypeAttrubute::Empty, addr_typ)
    }

    pub fn new_heap(typ: TypeValue, attr: TypeAttrubute) -> Self {
        Type::_new(typ, attr, TypeAddrType::Heap)
    }

    pub fn new_empty() -> Self {
        Type::_new(TypeValue::Empty, TypeAttrubute::Empty, TypeAddrType::Stack)
    }

    pub fn new_null() -> Self {
        Type::_new(TypeValue::Null, TypeAttrubute::Empty, TypeAddrType::Stack)
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

#[derive(Clone, Debug, PartialEq, Hash, Eq, Default, FieldGet, FieldGetClone
    , NewWithAll, FieldGetMove)]
pub struct AddressKey {
    index: u64,
    /*
     * 为复合类型准备的偏移量
     * */
    offset: usize,
    lengthen_offset: usize,
    scope: usize
}

impl AddressKey {
    pub fn clone_with_scope_plus(&self, scope: usize) -> Self {
        let mut o = self.clone();
        o.scope += scope;
        o
    }

    pub fn new(index: u64) -> Self {
        AddressKey::new_with_all(index, 0, 0, 0)
    }

    pub fn new_with_scope(index: u64, scope: usize) -> Self {
        AddressKey::new_with_all(index, 0, 0, scope)
    }

    pub fn new_with_offset(index: u64, offset: usize) -> Self {
        AddressKey::new_with_all(index, offset, 0, 0)
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum AddressType {
    Static,
    Stack,
    Heap,
    ParamRef(usize),
    AddrRef,
    Invalid
}

impl Default for AddressType {
    fn default() -> Self {
        AddressType::Invalid
    }
}

pub enum AddressNodeType {
    Branches,
    Leaf
}

#[derive(Debug, Clone, Default, PartialEq
    , Hash, Eq, FieldGet, FieldGetClone
    , FieldGetMove)]
pub struct AddressValue {
    typ: AddressType,
    addr: AddressKey
}

impl AddressValue {
    pub fn scope_ref(&self) -> &usize {
        self.addr_ref().scope_ref()
    }

    pub fn scope_clone(&self) -> usize {
        self.addr_ref().scope_ref().clone()
    }

    pub fn offset_clone(&self) -> usize {
        self.addr_ref().offset_clone()
    }

    pub fn addr_index_clone(&self) -> usize {
        self.addr_ref().index_clone() as usize
    }

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

