use crate::grammar::{GrammarParser
    , ExpressContext, Grammar
    , LoadVariantContext, LoadVariantContextValue};
use crate::token::TokenMethodResult;
use crate::token::{self, Token, TokenOperType, TokenAttrubute, TokenContext
    , TokenType};
use crate::lexical::CallbackReturnStatus;

pub struct IdToken {
    context: TokenContext
}

lazy_static!{
    static ref ID_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl IdToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(
        token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
        , express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        let mut token_value = grammar.take_next_one().token_value();
        match grammar.skip_white_space_token() {
            Some(tp) => {
                let next = tp.as_ref::<T, CB>();
                match next.context_token_type() {
                    TokenType::Colon => {
                    },
                    _ => {
                        /*
                         * 后面不是 : 也不是 . 号 => id
                         * */
                        let context = LoadVariantContext::new_with_all(
                            LoadVariantContextValue::Single(token_value));
                        grammar.grammar_context().cb.load_variant(context);
                    }
                }
            },
            None => {
                /*
                 * id 后面是 EOF => id
                 * */
                let context = LoadVariantContext::new_with_all(
                    LoadVariantContextValue::Single(token_value));
                grammar.grammar_context().cb.load_variant(context);
            }
        }
        TokenMethodResult::End
    }
}

impl IdToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*ID_TOKEN_ATTRUBUTE,
            nup: IdToken::nup,
            led: token::default_led
        }
    }
}


