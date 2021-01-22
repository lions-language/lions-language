use libcommon::ptr::{HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext, BreakNotagStmtContext};
use crate::grammar::{BlockDefineContext, LoopStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn break_process(&mut self) {
        /*
         * 跳过 break 关键字
         * */
        self.skip_next_one();
        /*
         * 检测 break 之后有没有 标签
         * */
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => tp,
            None => {
                /*
                 * while 后面没有token
                 *  => while 语句后面必须要有表达式
                 * */
                self.panic("expect expr, but arrive IOEof");
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::NewLine
                | TokenType::Semicolon => {
                /*
                 * break 之后没有标签
                 * */
                self.process_break_notag();
            },
            TokenType::Id => {
                /*
                 * break 之后有标签
                 * */
                self.process_break_withtag();
            },
            _ => {
                self.panic(&format!("expect newline / id but meet {:?}"
                        , next.context_token_type()));
            }
        }
    }

    fn process_break_notag(&mut self) {
        let context = BreakNotagStmtContext::new_with_all();
        check_desc_result!(self, self.cb().break_notag_stmt(context));
    }

    fn process_break_withtag(&mut self) {
        unimplemented!();
    }
}
