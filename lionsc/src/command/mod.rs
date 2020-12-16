use command_option::flag::{Flag, ItemValue};
use std::path::PathBuf;

const COMPILE_TYPE: &str = "-ct";
const COMPILE_LIB: &str = "--lib";
const COMPILE_BIN: &str = "--bin";
const DEPEND_PACKAGE: &str = "-dp";

pub enum CompileType {
    Bin,
    Lib
}

impl Default for CompileType {
    fn default() -> Self {
        CompileType::Bin
    }
}

pub struct DependPackage {
    package_name: String,
    package_path: PathBuf
}

pub struct CommandOption {
    pub compile_type: CompileType,
    pub depend_packages: Vec<DependPackage>
}

pub fn parse() -> CommandOption {
    let mut flag = Flag::new();
    let compile_type = flag.reg_string(String::from(COMPILE_TYPE)
        , String::from("localhost"), String::from("compile type --lib / --bin"));
    let depend_package = flag.reg_lengthen_str_vec(String::from(DEPEND_PACKAGE)
        , vecdeque![String::from("")], String::from("depend package"));
    flag.parse();
    let depend_packages = package_parse::package_parse(depend_package);
    let mut ct = CompileType::Bin;
    let compile_type = read_string!(compile_type);
    if compile_type == COMPILE_LIB {
        ct = CompileType::Lib;
    } else if compile_type == COMPILE_BIN {
        ct = CompileType::Bin;
    }
    CommandOption {
        compile_type: ct,
        depend_packages: depend_packages
    }
}

mod package_parse;

