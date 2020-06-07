#[derive(Debug)]
pub enum TokenType {
    Unknown,
    Plus,
    NewLine
}

impl Default for TokenType {
    fn default() -> Self {
        TokenType::Unknown
    }
}

pub trait Token {
    fn nup(&self, context: &TokenContext);
    fn led(&self, context: &TokenContext);
    fn context(&self) -> &TokenContext;
}

pub struct TokenContext {
    // 所在行号
    pub line: u64,
    // 列号
    pub col: u64,
    // token类型
    pub token_type: TokenType,
}

// 不需要实现 nup / led 方法的 token 结构
pub struct NoFunctionToken {
    context: TokenContext
}

impl Token for NoFunctionToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl NoFunctionToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}
