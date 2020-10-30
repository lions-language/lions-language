use crate::lexical::{LexicalParser, CallbackReturnStatus};
use crate::grammar::{Grammar};
use std::collections::{HashMap};

pub struct UndefineFunction<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> {
    lexical_parser: LexicalParser<T, CB>
}

pub struct Module<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> {
    undef_funcs: HashMap<String, UndefineFunction<T, CB>>
}

pub struct ModuleStack<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> {
    modules: Vec<Module<T, CB>>
}

mod stack;
mod module;
mod undefine_function;

