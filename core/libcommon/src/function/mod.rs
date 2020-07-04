use std::cmp::Eq;
use std::hash::Hash;

#[derive(Eq, PartialEq, Hash)]
pub enum FunctionKey {
    /*
     * 如果是类似原生方法的类型, function key 是不需要字符串拼接的, 在 rust编译期就可以知道
     * */
    Static(&'static str),
    Dynamic(String)
}

