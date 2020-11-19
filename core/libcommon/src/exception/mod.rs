use std::process;

pub fn exit<S: std::fmt::Debug>(msg: S) {
    println!("{:?}", msg);
    process::exit(0);
}

