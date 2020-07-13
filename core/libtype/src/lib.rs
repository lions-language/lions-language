use primeval::{PrimevalType};

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
pub struct StructObjectPtr(usize);

impl StructObjectPtr {
    pub fn from_ref(item: &StructObject) -> Self {
        Self(item as *const StructObject as usize)
    }

    pub fn new_null() -> Self {
        Self(0)
    }

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn as_ref(&self) -> &StructObject {
        unsafe {
            (self.0 as *const StructObject).as_ref().expect("should not happend")
        }
    }

    pub fn clone(&self) -> Self {
        Self(self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Structure {
    /*
     * 因为每一个结构的类型信息在整个系统中只有一份, 所以这里将结构的内存指针存储下来
     * 之后获取类型 string 的时候, 就只要访问地址中的字符串就可以, 降低内存消耗, 提高效率
     * */
    struct_obj_ptr: StructObjectPtr
}

impl Structure {
    pub fn new(struct_obj_ptr: StructObjectPtr) -> Self {
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
pub struct Primeval {
    pub typ: PrimevalType,
    pub ptr: bool
}

impl Primeval {
    pub fn new(typ: PrimevalType) -> Self {
        Self{
            typ: typ,
            ptr: false
        }
    }

    pub fn new_with_ptr(typ: PrimevalType, ptr: bool) -> Self {
        Self {
            typ: typ,
            ptr: ptr
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
