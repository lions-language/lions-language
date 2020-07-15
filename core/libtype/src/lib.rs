use libcommon::ptr::RefPtr;
use crate::primeval::PrimevalType;

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
    pub typ: PrimevalType,
    pub attr: TypeAttrubute
}

impl Primeval {
    pub fn new(typ: PrimevalType) -> Self {
        Self{
            typ: typ,
            attr: TypeAttrubute::Move
        }
    }

    pub fn new_with_attr(typ: PrimevalType, attr: TypeAttrubute) -> Self {
        Self {
            typ: typ,
            attr: attr
        }
    }
}

#[derive(Debug, Clone)]
pub enum Type {
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

pub mod function;
pub mod primeval;
pub mod typ;
pub mod module;
pub mod instruction;

