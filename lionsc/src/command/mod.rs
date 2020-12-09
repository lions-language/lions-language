use command_option::flag::{Flag};

const COMPILE_TYPE: &str = "-t";
const COMPILE_LIB: &str = "--lib";
const COMPILE_BIN: &str = "--bin";

pub enum CompileType {
    Bin,
    Lib
}

impl Default for CompileType {
    fn default() -> Self {
        CompileType::Bin
    }
}

#[derive(Default)]
pub struct CommandOption {
    pub compile_type: CompileType
}

pub fn parse() -> CommandOption {
    let mut command_option = CommandOption::default();
    let mut flag = Flag::new();
    {
        let compile_type = flag.reg_string(String::from(COMPILE_TYPE)
            , String::from("localhost"), String::from("compile type --lib / --bin"));
        let compile_type = read_string!(compile_type);
        if compile_type == COMPILE_LIB {
            command_option.compile_type = CompileType::Lib;
        } else if compile_type == COMPILE_BIN {
            command_option.compile_type = CompileType::Bin;
        }
    }
    flag.parse();
    command_option
}

