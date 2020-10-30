use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> LexicalParser<T, CB> {
    pub fn backslash_n(&mut self) {
        // 跳过 \n 号
        self.content.skip_next_one();
        /*
         * 查看是否是结尾
         * */
        let mut is_io_eof = false;
        self.lookup_next_one_with_cb_wrap(|_, _| {
        }, |_| {
            is_io_eof = true;
        });
        self.push_token_newline();
        if !is_io_eof {
            self.add_one_line();
        }
        // 因为 不需要关心 \n 后面是什么, 所以不需要再调用回调, 获取后面的源码字节数组
    }
}

