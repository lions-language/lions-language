use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use multiplication::MultiplicationToken;
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn start_multiplication(&mut self) {
        let context = self.build_token_context(TokenType::Multiplication);
        self.push_to_token_buffer(Box::new(MultiplicationToken::new(context)));
    }

    fn start_multiplication_equal(&mut self) {
    }

    pub fn start_process(&mut self) {
        /*
         * 跳过 *
         * */
        self.content.skip_next_one();
        /*
         * 查看下一个字符
         * */
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                '=' => {
                    /*
                     * 乘等于
                     * */
                    parser.start_multiplication_equal();
                },
                _ => {
                    /*
                     * 乘号
                     * */
                    parser.start_multiplication();
                }
            }
        }, |parser| {
        });
    }
}

mod multiplication;
