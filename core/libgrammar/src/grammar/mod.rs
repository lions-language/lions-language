use crate::lexical::{LexicalParser, CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType};
use crate::control::grammar::GrammarControl;

pub struct GrammarContext {
}

pub struct GrammarParser<T: FnMut() -> CallbackReturnStatus> {
    control: GrammarControl<T>,
    context: GrammarContext,
    current_token: TokenPointer
}

impl<T: FnMut() -> CallbackReturnStatus> GrammarParser<T> {
    pub fn parser(&mut self) {
        loop {
            match self.control.lookup_next_one_ptr() {
                Some(p) => {
                    self.select(&p);
                },
                None => {
                    break;
                }
            }
        }
    }

    fn select(&mut self, token: &TokenPointer) {
        match token.as_ref::<T>().context().token_type {
            TokenType::If => {
            },
            _ => {
                self.expression_process(token);
            }
        }
    }

    /*
     * 必须在 token 没有释放的时候调用
     * */
    fn update_current_token(&mut self, token: TokenPointer) {
        *&mut self.current_token = token;
    }

    fn panic(&self, msg: &str) {
        self.control.panic(msg);
    }

    pub fn new(grammar_control: GrammarControl<T>,
            grammar_context: GrammarContext) -> Self {
        Self {
            control: grammar_control,
            context: grammar_context,
            current_token: TokenPointer::new_null()
        }
    }
}

mod expression;

mod test {
    use super::*;
    use crate::lexical::VecU8;

    use std::fs;
    use std::io::Read;

    #[test]
    fn grammar_parser_test() {
        let mut file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(err) => {
                panic!("read file error");
            }
        };
        let mut lexical_parser = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let mut f_ref = f.by_ref();
            match f_ref.take(1).read_to_end(&mut v) {
                Ok(len) => {
                    if len == 0 {
                        return CallbackReturnStatus::End;
                    } else {
                        return CallbackReturnStatus::Continue(VecU8::from_vec_u8(v));
                    }
                },
                Err(_) => {
                    return CallbackReturnStatus::End;
                }
            }
        });
        let mut grammar_control = GrammarControl::new(lexical_parser);
        let grammar_context = GrammarContext{
        };
        let mut grammar_parser = GrammarParser::new(grammar_control, grammar_context);
        grammar_parser.parser();
    }
}

