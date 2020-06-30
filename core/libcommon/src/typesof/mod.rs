#[derive(Debug)]
pub struct StructItem {
    pub name: String
}

impl StructItem {
    pub fn new(name: String) -> Self {
        Self {
            name: name
        }
    }
}

#[derive(Debug)]
pub struct PointerType {
}

#[derive(Debug)]
pub enum Type {
    /*
     * 原生类型
     * */
    Primeval,
    Structure(StructItem),
    Ptr(PointerType)
}
