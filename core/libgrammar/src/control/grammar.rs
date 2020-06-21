use crate::lexical::{LexicalParser, CallbackReturnStatus, TokenPointer, TokenVecItem};
use crate::grammar::Grammar;

/*
 * grammar control
 * */
pub struct GrammarControl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    lexical_parser: LexicalParser<T, CB>
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarControl<T, CB> {
    pub fn lookup_next_one_ptr(&mut self) -> Option<TokenPointer> {
        self.lexical_parser.lookup_next_one_ptr()
    }

    pub fn take_next_one(&mut self) -> TokenVecItem<T, CB> {
        self.lexical_parser.take_next_one()
    }

    pub fn panic(&self, msg: &str) {
        self.lexical_parser.panic(msg);
    }

    pub fn new(lexical_parser: LexicalParser<T, CB>) -> Self {
        Self {
            lexical_parser: lexical_parser
        }
    }
}

