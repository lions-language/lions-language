use crate::lexical::{LexicalParser, CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

pub trait Grammar {
    fn express_const_number(&self, value: TokenValue) {
        println!("express_const_number");
    }
    fn operator_plus(&self, value: TokenValue) {
        println!("operator_plus");
    }
}

pub struct GrammarContext<CB>
    where CB: Grammar {
    pub cb: CB
}

pub type ExpressEndFunc<T, CB> = fn(&TokenVecItem<T, CB>) -> bool;

pub struct ExpressContext<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    pub end_f: ExpressEndFunc<T, CB>
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> ExpressContext<T, CB> {
    pub fn new(end_f: ExpressEndFunc<T, CB>) -> Self {
        Self {
            end_f: end_f
        }
    }
}

pub struct GrammarParser<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    lexical_parser: LexicalParser<T, CB>,
    context: &'a mut GrammarContext<CB>
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn parser(&mut self) {
        loop {
            match self.lexical_parser.lookup_next_one_ptr() {
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
        match token.as_ref::<T, CB>().context_ref().token_type {
            TokenType::If => {
            },
            TokenType::NewLine => {
                self.take_next_one();
            },
            _ => {
                self.expression_process(token);
            }
        }
    }

    pub fn take_next_one(&mut self) -> TokenVecItem<T, CB> {
        self.lexical_parser.take_next_one()
    }

    pub fn lookup_next_one_ptr(&mut self) -> Option<TokenPointer> {
        self.lexical_parser.lookup_next_one_ptr()
    }

    pub fn grammar_context(&mut self) -> &mut GrammarContext<CB> {
        self.context
    }

    pub fn panic(&self, msg: &str) {
        self.lexical_parser.panic(msg);
    }

    pub fn new(lexical_parser: LexicalParser<T, CB>,
            grammar_context: &'a mut GrammarContext<CB>) -> Self {
        Self {
            lexical_parser: lexical_parser,
            context: grammar_context
        }
    }
}

mod expression;

mod test {
    use super::*;
    use crate::lexical::VecU8;

    use std::fs;
    use std::io::Read;

    struct TestGrammar {
    }

    impl Grammar for TestGrammar {
    }

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
        let mut grammar_context = GrammarContext{
            cb: TestGrammar{}
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}

