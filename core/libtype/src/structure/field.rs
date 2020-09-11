use super::{StructField, StructDefine};
use crate::{TypeValue};

impl StructField {
    pub fn clone_with_index_plus(&self, index: usize) -> Self {
        let mut f = self.clone();
        *f.index_mut() += index;
        f
    }

    pub fn length(&self) -> usize {
        match self.typ_ref().typ_ref() {
            TypeValue::Structure(s) => {
                let define = s.struct_obj_ref().pop();
                let len = define.member_length();
                s.struct_obj_ref().push(define);
                len
            },
            _ => {
                0
            }
        }
    }
}

