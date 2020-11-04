use libresult::{DescResult};
use super::{GrammarParser, Grammar
    , ModuleStmtContext};
use crate::token::{TokenType, TokenData};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn use_process(&mut self) {
        /*
         * 跳过 use 关键字
         * */
        self.skip_next_one();
        /*
         * 分析 字符串
         * 1. * => 表示当前目录的所有 lions 文件
         * */
    }
}
