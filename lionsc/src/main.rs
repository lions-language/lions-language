#[macro_use]
extern crate command_option;

fn main() {
    let command_option = command::parse();
    match &command_option.compile_type {
        command::CompileType::Bin => {
        },
        command::CompileType::Lib => {
            unimplemented!();
        }
    }
}

mod command;
