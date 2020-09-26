use crate::define::FunctionDefine;
use crate::define_stream::DefineStream;
use std::collections::VecDeque;

pub struct FunctionDefineDispatch<'a> {
    /*
     * 只是用于保存 FunctionDefine, 使 作用域结束后不被销毁
     * */
    processing_funcs: VecDeque<FunctionDefine>,
    define_stream: &'a mut DefineStream
}

pub struct BlockDefineDispatch<'a> {
    define_stream: &'a mut DefineStream
}

mod function;
mod block;
