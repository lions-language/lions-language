use libmacro::{FieldGet, FieldGetClone};

#[derive(FieldGet, FieldGetClone)]
struct Test {
    f1: String,
    f2: u64
}

impl Test {
    fn new() -> Self {
        Self {
            f1: String::from("hello world"),
            f2: 0
        }
    }
}

pub fn test() {
    let t = Test::new();
    let f1_ref = t.f1_ref();
    let f2_ref = t.f2_ref();
    let f1_clone = t.f1_clone();
    println!("f1_ref: {}, f1_clone: {}, f2_ref: {}", f1_ref, f1_clone, f2_ref);
}

