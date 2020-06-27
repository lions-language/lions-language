use crate::lexical::{CallbackReturnStatus, LexicalParser};
use crate::grammar::{Grammar};
use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn colon(&mut self) {
        let context = self.build_token_context(TokenType::Colon);
        self.push_to_token_buffer(colon::ColonToken::new(context));
    }

    pub fn colon_process(&mut self) {
        /*
         * 跳过 :
         * */
        self.content.skip_next_one();
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                '=' => {
                    /*
                     * :=
                     * */
                },
                _ => {
                    /*
                     * :
                     * */
                    parser.colon();
                }
            }
        }, |parser| {
        });
    }
}
            
pub mod colon;