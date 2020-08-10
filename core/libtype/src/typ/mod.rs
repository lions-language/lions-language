use crate::{Type, TypeValue, StructObject};

impl Type {
    pub fn to_str(&self) -> &str {
        match self.typ_ref() {
            TypeValue::Primeval(v) => {
                v.typ.to_str()
            },
            TypeValue::Structure(sp) => {
                sp.struct_obj_ptr.as_ref::<StructObject>().name_str()
            },
            TypeValue::Any => {
                consts::ANY_TYPE
            },
            TypeValue::Empty => {
                consts::EMPTY_TYPE
            },
            TypeValue::Null => {
                consts::NULL_TYPE
            }
        }
    }

    pub fn to_attrubute_str(&self) -> &str {
        self.attr_ref().to_str()
    }
}

mod consts;
