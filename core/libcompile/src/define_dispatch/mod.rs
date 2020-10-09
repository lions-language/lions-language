use crate::define::{FunctionDefineObject, BlockDefineObject};
use crate::define_stream::DefineStream;
use std::collections::VecDeque;

pub struct FunctionDefineDispatch<'a> {
    /*
     * 只是用于保存 FunctionDefine, 使 作用域结束后不被销毁
     * */
    // processing_funcs: VecDeque<FunctionDefineObject>,
    define_stream: &'a mut DefineStream
}

pub struct BlockDefineDispatch<'a> {
    processing_blocks: VecDeque<BlockDefineObject>,
    define_stream: &'a mut DefineStream
}

pub mod function;
mod block;
