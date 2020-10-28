use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use star::StarToken;
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn start_star(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Star);
        self.push_to_token_buffer(StarToken::new(context));
    }

    fn start_star_equal(&mut self) {
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
                    parser.start_star_equal();
                },
                _ => {
                    /*
                     * 乘号
                     * */
                    parser.start_star();
                }
            }
        }, |parser| {
        });
    }
}

mod star;
