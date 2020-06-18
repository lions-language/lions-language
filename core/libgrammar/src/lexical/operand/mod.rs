use libcommon::token::{Token, TokenOperType, TokenAttrubute, TokenContext};

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
    context: TokenContext
}

impl Token for OperandToken {
    fn context(&self) -> &TokenContext {
        return &self.context;
    }   

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*operand_token_attrubute
    }   
}

impl OperandToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }   
}


