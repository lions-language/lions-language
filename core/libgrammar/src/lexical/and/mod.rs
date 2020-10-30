use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> LexicalParser<T, CB> {
    pub fn and_process(&mut self) {
        /*
         * 跳过 &
         * */
        self.content.skip_next_one();
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                '&' => {
                    // &&
                    unimplemented!();
                },
                _ => {
                    // &
                    parser.and_single();
                }
            }
        }, |parser| {
            parser.and_single();
        });
    }

    fn and_single(&mut self) {
        let context = self.build_token_context_without_data(TokenType::And);
        self.push_to_token_buffer(and::AndToken::new(context));
    }
}

mod and;

