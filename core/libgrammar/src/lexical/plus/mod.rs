use super::{LexicalParser, TokenVecItem, CallbackReturnStatus};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn start_with_plus(&mut self, tokens: &mut Vec<TokenVecItem>) {
        self.lookup_next_n(1);
    }
}

mod plus;
mod plus_plus;

