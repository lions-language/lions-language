use command_option::flag::{Value, ItemValue};
use libcommon::exception::{exit};
use std::path::{Path, PathBuf};
use crate::command::DependPackage;

pub fn package_parse(value: Value) -> Vec<DependPackage> {
    const GROUP: usize = 2;
    let value = read_vector!(value);
    if value.is_empty() || (value.len() % GROUP != 0) {
        exit("depend package must be a group of two");
    }
    let mut index = 0;
    let mut items = Vec::with_capacity(value.len() / GROUP);
    while index < value.len() {
        let package_name = read_string_item!(value[index]);
        let package_path = read_string_item!(value[index+1]);
        items.push(DependPackage{
            package_name: package_name.to_string(),
            package_path: Path::new(package_path).to_path_buf()
        });
        index += GROUP;
    }
    items
}

