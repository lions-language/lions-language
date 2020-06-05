type NupFunc = fn();
type LedFunc = fn();

pub enum TokenType {
}

pub trait Token {
	fn nup(&self, context: &TokenContext);
	fn led(&self, context: &TokenContext);
	fn context(&self) -> &TokenContext;
}

pub struct TokenContext {
    // 文件路径
    pub file: String,
    // 所在行号
    pub line: i64,
    // 列号
    pub col: i64,
    // token类型
    pub token_type: TokenType,
    // nup 方法
    pub nup: NupFunc,
    // led 方法
    pub led: LedFunc
}
