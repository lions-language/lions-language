use crate::{Type, StructObject};

impl Type {
    pub fn to_str(&self) -> &str {
        match self {
            Type::Primeval(v) => {
                v.typ.to_str()
            },
            Type::Structure(sp) => {
                sp.struct_obj_ptr.as_ref::<StructObject>().name_str()
            },
            Type::Empty => {
                consts::EMPTY_TYPE
            }
        }
    }

    pub fn to_attrubute_str(&self) -> &str {
        match self {
            Type::Primeval(v) => {
                v.attr.to_str()
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

mod consts;
