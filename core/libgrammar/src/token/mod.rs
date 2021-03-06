use crate::lexical::{CallbackReturnStatus, TokenVecItem};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::{TypeAttrubute};
use libmacro::{FieldGet, NewWithAll};
use std::cmp::{PartialEq, Eq};

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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    // <
    LeftAngularBracket,
    // <=
    LeftAngularBracketEqual,
    // >
    RightAngularBracket,
    // \r | \r\n | \n
    NewLine,
    // if
    If,
    // else
    Else,
    // elif
    ElseIf,
    // for
    For,
    // while
    While,
    // loop
    Loop,
    // func
    Function,
    // let
    Let,
    // var
    Var,
    // return
    Return,
    // struct
    Structure,
    // interface
    Interface,
    // enum
    Enum,
    // true
    True,
    // false
    False,
    // import
    Import,
    // relmod
    Relmod,
    // module
    Module,
    // use
    Use,
    // as
    As,
    // break
    Break,
    // continue
    Continue,
    // ->
    RightArrow,
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
    Star,
    // /
    Division,
    // ;
    Semicolon,
    // :
    Colon,
    // ::
    ColonColon,
    // ,
    Comma,
    // .
    Point,
    // ..
    TwoPoint,
    // ..=
    TwoPointEqual,
    // ...
    ThreePoint,
    // &
    And,
    // 注释
    Annotate,
    Id,
    // is
    Is,
    // impl
    Impl,
    Const(PrimevalType),
    PrimevalType(PrimevalType)
}

impl TokenType {
    pub fn is_integer(&self) -> bool {
        match self {
            TokenType::Const(t) => {
                t.is_integer()
            },
            _ => {
                false
            }
        }
    }
}

#[derive(Debug)]
pub enum TokenData {
    Annotate(Vec<u8>),
    Id(String),
    Const(PrimevalData),
}

impl Default for TokenType {
    fn default() -> Self {
        TokenType::Unknown
    }
}

#[derive(Debug)]
pub enum TokenOperType {
    NoOperate,
    Operand,
    Operator
}

lazy_static!{
    pub static ref DEFAULT_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute::default();
}

pub fn default_token_attrubute() -> &'static TokenAttrubute {
    return &*DEFAULT_TOKEN_ATTRUBUTE;
}

#[derive(Debug)]
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

/*
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

    pub fn token_type(&self) -> &TokenType {
        &self.context.token_type
    }

    pub fn move_token_type(self) -> TokenType {
        self.context.token_type
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
*/

#[derive(Debug, Default, FieldGet, NewWithAll)]
pub struct TokenValue {
    pub token_type: TokenType,
    pub token_data: Option<TokenData>
}

impl TokenValue {
    pub fn print_token_type(&self, msg: Option<&str>) {
        match msg {
            Some(s) => {
                println!("{} {:?}", s, &self.token_type);
            },
            None => {
                println!("{:?}", &self.token_type);
            }
        }
    }

    pub fn print_token_data(&self) {
        println!("{:?}", &self.token_data);
    }

    /*
     * 因为 TokenType 中都是枚举, 所以拷贝的消耗非常小
     * */
    pub fn token_type_clone(&self) -> TokenType {
        self.token_type.clone()
    }

    pub fn token_data_unchecked(self) -> TokenData {
        self.token_data.expect("should not happend")
    }

    pub fn new(typ: TokenType, data: Option<TokenData>) -> Self {
        TokenValue::new_with_all(typ, data)
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

#[derive(Debug, Default)]
pub struct TokenContext {
    // 所在行号
    pub line: u64,
    // 列号
    pub col: u64,
    // token类型
    pub token_value: TokenValue
}

impl TokenContext {
    pub fn token_type(&self) -> &TokenType {
        &self.token_value.token_type
    }

    pub fn token_type_move(self) -> TokenType {
        self.token_value.token_type
    }

    pub fn token_data_unchecked(self) -> TokenData {
        self.token_value.token_data.expect("token data is None")
    }
}

type NupFunc<T, CB> = fn(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
    , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult;
type LedFunc<T, CB> = fn(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
    , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult;

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

    pub fn nup(&self, grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        (self.nup)(self, grammar, express_context)
    }

    pub fn led(&self, grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        (self.led)(self, grammar, express_context)
    }

    pub fn context_token_type(&self) -> &TokenType {
        &self.context.token_value.token_type
    }

    pub fn context_token_value_ref(&self) -> &TokenValue {
        &self.context.token_value
    }

    pub fn token_value(self) -> TokenValue {
        self.context.token_value
    }
}

pub fn default_nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
    , grammar: &mut GrammarParser<T, CB>
    , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
    TokenMethodResult::None
}

pub fn default_led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
    , grammar: &mut GrammarParser<T, CB>
    , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
    TokenMethodResult::None
}

/*
 * 无操作 token 的统一结构 (注释 token ...)
 * */
lazy_static!{
    static ref NOOPERATE_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute{
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
            attrubute: &*NOOPERATE_TOKEN_ATTRUBUTE,
            nup: default_nup,
            led: default_led
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore]
    fn extract_token_data_test() {
        let td = TokenData::Id(String::from("hello"));
        let v = extract_token_data!(td, Id);
        println!("{}", v);
    }
}

