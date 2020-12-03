use std::process;

pub fn exit<S: std::fmt::Display>(msg: S) {
    println!("{}", msg);
    process::exit(0);
}

