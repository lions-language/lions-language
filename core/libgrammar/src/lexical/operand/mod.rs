use crate::token::{self, Token, TokenOperType, TokenAttrubute, TokenContext};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::Grammar;

/*
 * 操作数 的统一实现
 * */
lazy_static!{
    static ref operand_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0, 
        oper_type: &TokenOperType::Operand
    };  
}

pub struct OperandToken {
}

impl OperandToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*operand_token_attrubute,
            nup: token::default_nup,
            led: token::default_led
        }
    }   
}


