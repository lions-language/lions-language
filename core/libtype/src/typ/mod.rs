use crate::Type;

impl Type {
    pub fn to_str(&self) -> &str {
        match self {
            Type::Primeval(v) => {
                return &v.typ.to_str();
            },
            Type::Structure(_) => {
                unimplemented!();
            }
        }
    }
}
