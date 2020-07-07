use libgrammar::token::{TokenValue, TokenType};
use libcommon::function::{FunctionKey};
use super::Compile;

impl Compile {
    pub fn tokenvalue_type_str<'a>(&self, value: &'a TokenValue) -> &'a str {
        match value.token_type() {
            TokenType::Const(pt) => {
                pt.to_str()
            },
            _ => {
                unimplemented!();
            }
        }
    }

    pub fn splice_binary_operator_funckey(&self, left_str: &str, right_str: &str
        , op: &str) -> FunctionKey {
        let len = left_str.len() + 1 + op.len() + 1 + right_str.len();
        let mut key = String::with_capacity(len);
        key.push_str(left_str);
        key.push('_');
        key.push_str(op);
        key.push('_');
        key.push_str(right_str);
        FunctionKey::new(key)
    }
}
