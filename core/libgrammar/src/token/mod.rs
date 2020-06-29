use crate::lexical::{CallbackReturnStatus, TokenVecItem};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub enum TokenType {
    Unknown,
    // +
    Plus,
    // ++
    PlusPlus,
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
    // func
    Function,
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
    // ;
    Semicolon,
    // :
    Colon,
    // ,
    Comma,
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

impl TokenType {
    pub fn format(&self) -> &'static str {
        match self {
            TokenType::Plus => {
                "+"
            },
            TokenType::Minus => {
                "-"
            },
            TokenType::Multiplication => {
                "*"
            },
            TokenType::Number(_) => {
                "number"
            },
            _ => {
                "unknow"
            }
        }
    }
}

pub enum TokenOperType {
    NoOperate,
    Operand,
    Operator
}

lazy_static!{
    pub static ref default_token_attrubute: TokenAttrubute = TokenAttrubute::default();
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

#[derive(Debug)]
pub enum TokenMethodResult {
    None,
    Continue,
    // 正常结束
    End,
    // 异常
    Panic,
    // 语句结束
    StmtEnd,
    // () 结束
    ParentheseEnd
}

pub struct TokenValue {
    pub context: TokenContext,
    pub token_attrubute: &'static TokenAttrubute
}

impl TokenValue {
    pub fn from_token<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: TokenVecItem<T, CB>) -> Self {
        Self {
            token_attrubute: token.token_attrubute(),
            context: token.context,
        }
    }

    pub fn print_token_type(&self, msg: Option<&str>) {
        match msg {
            Some(s) => {
                println!("{} {:?}", s, &self.context.token_type);
            },
            None => {
                println!("{:?}", &self.context.token_type);
            }
        }
    }
}

/*
pub trait Token<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    fn nup(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
    fn led(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*default_token_attrubute
    }
    fn context_ref(&self) -> &TokenContext;
    fn context(self) -> TokenContext;
}
*/

#[derive(Default)]
pub struct TokenContext {
    // 所在行号
    pub line: u64,
    // 列号
    pub col: u64,
    // token类型
    pub token_type: TokenType,
}

type NupFunc<T, CB> = fn(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult;
type LedFunc<T, CB> = fn(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult;

pub struct Token<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    pub context: TokenContext,
    pub attrubute: &'static TokenAttrubute,
    pub nup: NupFunc<T, CB>,
    pub led: LedFunc<T, CB>
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> {
    pub fn context_ref(&self) -> &TokenContext {
        &self.context
    }

    pub fn token_attrubute(&self) -> &'static TokenAttrubute {
        self.attrubute
    }

    pub fn nup(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        (self.nup)(self, grammar, express_context)
    }

    pub fn led(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        (self.led)(self, grammar, express_context)
    }

    pub fn context_format(&self) -> &'static str {
        self.context.token_type.format()
    }
}

pub fn default_nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
    TokenMethodResult::None
}

pub fn default_led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
    TokenMethodResult::None
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

impl NoOperateToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*nooperate_token_attrubute,
            nup: default_nup,
            led: default_led
        }
    }
}

