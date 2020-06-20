use crate::lexical::{LexicalParser, CallbackReturnStatus, TokenPointer};

/*
 * grammar control
 * */
pub struct GrammarControl<T: FnMut() -> CallbackReturnStatus> {
    lexical_parser: LexicalParser<T>
}

impl<T: FnMut() -> CallbackReturnStatus> GrammarControl<T> {
    pub fn lookup_next_one_ptr(&mut self) -> Option<TokenPointer> {
        self.lexical_parser.lookup_next_one_ptr()
    }
}

