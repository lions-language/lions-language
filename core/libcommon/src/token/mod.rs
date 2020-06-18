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
    // {
    LeftBigParenthese,
    // }
    RightBigParenthese,
    // *
    Multiplication,
    // /
    Division,
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

pub enum TokenOperType {
    NoOperate,
    Operand,
    Operator
}

lazy_static!{
    static ref default_token_attrubute: TokenAttrubute = TokenAttrubute::default();
}

pub struct TokenAttrubute {
    pub bp: &'static u8,
    pub oper_type: &'static TokenOperType
}

impl Default for TokenAttrubute {
    fn default() -> Self {
        Self{
            bp: &0,
            oper_type: &TokenOperType::NoOperate
        }
    }
}

pub trait Token {
    fn nup(&self, _context: &TokenContext) {
    }
    fn led(&self, _context: &TokenContext) {
    }
    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*default_token_attrubute
    }
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

/*
 * 无操作 token 的统一结构 (注释 token ...)
 * */
lazy_static!{
    static ref nooperate_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::NoOperate
    };
}

pub struct NoOperateToken {
    context: TokenContext
}

impl Token for NoOperateToken {
    fn context(&self) -> &TokenContext {
        return &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*nooperate_token_attrubute
    }
}

impl NoOperateToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

