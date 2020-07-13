use crate::Type;

impl Type {
    pub fn to_str(&self) -> &str {
        match self {
            Type::Primeval(v) => {
                v.typ.to_str()
            },
            Type::Structure(sp) => {
                sp.struct_obj_ptr.as_ref().name_str()
            },
            Type::Empty => {
                consts::EMPTY_TYPE
            }
        }
    }
}

mod consts;
