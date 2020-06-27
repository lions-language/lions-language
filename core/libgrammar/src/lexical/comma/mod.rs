use crate::lexical::{CallbackReturnStatus, LexicalParser};
use crate::grammar::{Grammar};
use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn comma(&mut self) {
        let context = self.build_token_context(TokenType::Comma);
        self.push_to_token_buffer(comma::CommaToken::new(context));
    }

    pub fn comma_process(&mut self) {
        /*
         * 跳过 :
         * */
        self.content.skip_next_one();
        self.comma();
        /*
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                _ => {
                    /*
                     * ,
                     * */
                    parser.comma();
                }
            }
        }, |parser| {
        });
        */
    }
}
            
pub mod comma;