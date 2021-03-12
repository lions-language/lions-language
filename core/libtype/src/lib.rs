use libcommon::ptr::{RefPtr, HeapPtr, Heap};
use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use crate::primeval::{PrimevalType, PrimevalData};
use crate::structure::{StructureData, StructDefine};
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StructObject(HeapPtr);

impl StructObject {
    pub fn pop(&self) -> Heap<StructDefine> {
        self.0.pop()
    }
    pub fn push(&self, v: Heap<StructDefine>) {
        self.0.push(v);
    }
    pub fn new(p: HeapPtr) -> Self {
        Self(p)
    }
}

#[derive(Debug, Clone, PartialEq, Eq
    , FieldGet, FieldGetClone)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceObject(HeapPtr);

impl InterfaceObject {
    pub fn pop(&self) -> Heap<InterfaceDefine> {
        self.0.pop()
    }
    pub fn push(&self, v: Heap<InterfaceDefine>) {
        self.0.push(v);
    }
    pub fn new(p: HeapPtr) -> Self {
        Self(p)
    }
}

#[derive(Debug, Clone, PartialEq, Eq
    , FieldGet, FieldGetClone)]
pub struct Interface {
    /*
     * 因为每一个结构的类型信息在整个系统中只有一份, 所以这里将结构的内存指针存储下来
     * 之后获取类型 string 的时候, 就只要访问地址中的字符串就可以, 降低内存消耗, 提高效率
     *
     * 在构造 结构类型时, 会从 interface_control 中找到 InterfaceObject 指针
     *  比如: let a = mod1::Test{};
     *  compile 阶段会通过 mod1 从 interface_control 中找到 InterfaceObject 指针, 然后通过这个指针, 构造
     *  Type对象, 调用 interface_control 获取方法定义
     * */
    interface_obj: InterfaceObject
}

impl Interface {
    pub fn new(interface_obj: InterfaceObject) -> Self {
        Self {
            interface_obj: interface_obj
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

    pub fn is_ref_as_assign(&self) -> bool {
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

    pub fn is_move_as_assign(&self) -> bool {
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

#[derive(Debug, Clone, PartialEq, Eq
    , FieldGet)]
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
    scope: usize,
    length: usize
}

impl AddressKey {
    pub fn clone_with_scope_plus(&self, scope: usize) -> Self {
        let mut o = self.clone();
        o.scope += scope;
        o
    }

    pub fn clone_with_index_plus(&self, n: usize) -> Self {
        let mut o = self.clone();
        o.index += n as u64;
        o
    }

    pub fn clone_use_index(&self, n: usize) -> Self {
        let mut o = self.clone();
        o.index = n as u64;
        o
    }

    pub fn new_single(index: u64) -> Self {
        AddressKey::new_with_all(index, 0, 0, 0, 0)
    }

    pub fn new_with_scope_single(index: u64, scope: usize) -> Self {
        AddressKey::new_with_all(index, 0, 0, scope, 0)
    }

    pub fn new_with_offset_single(index: u64, offset: usize) -> Self {
        AddressKey::new_with_all(index, offset, 0, 0, 0)
    }

    pub fn new_multi(index: u64, length: usize) -> Self {
        AddressKey::new_with_all(index, 0, 0, 0, length)
    }

    pub fn new_with_scope_multi(index: u64, scope: usize, length: usize) -> Self {
        AddressKey::new_with_all(index, 0, 0, scope, length)
    }

    pub fn new_with_offset_multi(index: u64, offset: usize, length: usize) -> Self {
        AddressKey::new_with_all(index, offset, 0, 0, length)
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum AddressType {
    Static,
    Stack,
    Heap,
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
    addr: AddressKey,
    root_typ: AddressType
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

    pub fn clone_with_index_scope_plus(&self
        , index: usize, scope: usize) -> Self {
        let mut addr = self.clone();
        *addr.addr_mut().index_mut() += index as u64;
        *addr.addr_mut().scope_mut() += scope as usize;
        addr
    }

    pub fn new_invalid() -> Self {
        Self::default()
    }

    pub fn new_with_root_typ(typ: AddressType, root_typ: AddressType
        , addr: AddressKey) -> Self {
        Self {
            typ: typ.clone(),
            addr: addr,
            root_typ: root_typ
        }
    }

    pub fn new(typ: AddressType, addr: AddressKey) -> Self {
        Self {
            typ: typ.clone(),
            addr: addr,
            root_typ: typ
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
pub mod interface;

