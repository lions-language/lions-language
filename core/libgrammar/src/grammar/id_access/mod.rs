use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, Grammar};
use crate::token::{TokenType, TokenValue, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn format_define(&mut self) {
        /*
         * 处理如: a is math::Get
         * env:
         *  1. 从 math 开始, 不要跳过 math
         * */
        let tp = self.skip_white_space_token();
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Id => {
                self.format_define_id();
            },
            _ => {
                self.panic(&format!("expect id, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }

    fn format_define_id(&mut self) {
        let first = self.take_next_one().token_value().token_data_unchecked();
        let first_name = extract_token_data!(first, Id);
        let tp = self.skip_white_space_token();
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::ColonColon => {
                self.format_define_colon_colon(first_name);
            },
            TokenType::RightParenthese => {
                self.format_define_single(first_name);
            },
            _ => {
                self.panic(&format!("expect id or right_parenthese, but meet {:?}", token.context_token_type()));
            }
        }
    }

    fn format_define_colon_colon(&mut self, name: String) {
    }

    fn format_define_single(&mut self, name: String) {
    }
}
