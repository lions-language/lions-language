use libmacro::{NewWithAll};

#[derive(NewWithAll)]
struct Test {
    f1: String,
    f2: u32
}

pub fn test() {
    let test = Test::new(String::from(""), 0);
}

