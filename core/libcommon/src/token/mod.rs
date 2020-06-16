#[derive(Debug)]
pub enum NumberValue {
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Float32(f32),
    Float64(f64)
}

#[derive(Debug)]
pub enum TokenType {
    Unknown,
    // +
    Plus,
    // -
    Minus,
    // =
    Equal,
    // ==
    EqualEqual,
    // \r | \r\n | \n
    NewLine,
    // if
    If,
    // else
    Else,
    // elif
    ElseIf,
    // (
    LeftParenthese,
    // )
    RightParenthese,
    // [
    LeftSquareBrackets,
    // ]
    RightSquareBrackets,
    // 注释
    Annotate(Vec<u8>),
    Id(String),
    Number(NumberValue),
    Str(Vec<u8>)
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
