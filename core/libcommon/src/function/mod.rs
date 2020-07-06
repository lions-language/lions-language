use std::cmp::Eq;
use std::hash::Hash;

/*
/*
 * TODO: 待优化, 考虑使用 phf_map (完美散列)
 * */
#[derive(Eq, PartialEq, Hash)]
pub enum FunctionKeyOld {
    /*
     * 如果是类似原生方法的类型, function key 是不需要字符串拼接的, 在 rust编译期就可以知道
     * */
    Static(&'static str),
    Dynamic(String)
}
*/

#[derive(Eq, PartialEq, Hash)]
pub struct FunctionKey(String);

impl FunctionKey {
    pub fn key_ref(&self) -> &str {
        &self.0
    }

    pub fn new(v: String) -> Self {
        Self(v)
    }
}

