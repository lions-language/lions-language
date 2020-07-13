use crate::Type;

pub struct Format {
}

impl Format {
    pub fn splice_type_funcstr(typ: &Type, func_str: &str) -> String {
        let mut s = String::new();
        s.push_str(typ.to_str());
        s.push_str(":");
        s.push_str(func_str);
        s
    }
}

