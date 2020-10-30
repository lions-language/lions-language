use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType, TokenData};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn push_token_annotate(&mut self, content: Vec<u8>) {
        /*
         * TODO: 目前的做法是忽略注释
         * 以后需要提供打印注释中内容的语法
         * */
        /*
        let context = self.build_token_context(TokenType::Annotate, TokenData::Annotate(content));
        self.push_to_token_buffer(annotate::AnnotateToken::new(context));
        */
    }
}

pub mod annotate;

