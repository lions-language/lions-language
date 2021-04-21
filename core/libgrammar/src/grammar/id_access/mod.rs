use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, Grammar, FormatDefine};
use crate::token::{TokenType, TokenValue, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn format_define(&mut self, end_token: TokenType) -> FormatDefine {
        /*
         * 处理如: a is math::Get
         * env:
         *  1. 从 math 开始, 不要跳过 math
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                self.panic("expect id, but arrive EOF");
                panic!();
            }
        };
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Id => {
                self.format_define_id(end_token)
            },
            _ => {
                self.panic(&format!("expect id, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }

    fn format_define_id(&mut self, end_token: TokenType) -> FormatDefine {
        let first = self.take_next_one().token_value().token_data_unchecked();
        let first_name = extract_token_data!(first, Id);
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                self.panic("expect `)` or `::`, but arrive EOF");
                panic!();
            }
        };
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::ColonColon => {
                self.format_define_colon_colon(first_name)
            },
            _ => {
                if &end_token == token.context_token_type() {
                    self.format_define_end_single(first_name)
                } else {
                    self.panic(&format!("expect id or {:?}, but meet {:?}", end_token, token.context_token_type()));
                    panic!();
                }
            }
        }
    }

    fn format_define_colon_colon(&mut self, name: String) -> FormatDefine {
        /*
         * 跳过 ::
         * */
        self.skip_next_one();
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                self.panic("expect id, but arrive EOF");
                panic!();
            }
        };
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Id => {
                self.format_define_end_multi(name)
            },
            _ => {
                self.panic(&format!("expect id, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }

    fn format_define_end_single(&mut self, name: String) -> FormatDefine {
        FormatDefine::new_with_all(None, name)
    }

    fn format_define_end_multi(&mut self, first: String) -> FormatDefine {
        let second = self.take_next_one().token_value().token_data_unchecked();
        let second_name = extract_token_data!(second, Id);
        FormatDefine::new_with_all(Some(first), second_name)
    }
}
