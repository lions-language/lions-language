#[macro_use]
extern crate command_option;
use command_option::flag::{Flag};

const COMPILE_TYPE: &'static str = "-t";
const COMPILE_LIB: &'static str = "--lib";
const COMPILE_BIN: &'static str = "--bin";

fn main() {
    let mut flag = Flag::new();
    let compile_type = flag.reg_string(String::from(COMPILE_TYPE)
        , String::from("localhost"), String::from("compile type --lib / --bin"));
    flag.parse();
}
