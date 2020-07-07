use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use id::IdToken;
use crate::grammar::Grammar;
use libhosttype::primeval::{PrimevalType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn id_push_keyword_token(&mut self, token_type: TokenType) {
        self.push_nooperate_token_to_token_buffer(token_type);
    }

    fn id(&mut self, s: &String) {
        /*
         * 存入 context
         * */
        let context = self.build_token_context(TokenType::Id(s.to_string()));
        self.push_to_token_buffer(IdToken::new(context));
    }

    fn id_kw_if(&mut self) {
        self.id_push_keyword_token(TokenType::If);
    }

    fn id_kw_else(&mut self) {
        /*
         * lions-language 支持 else if 写法
         * 但是在词法分析阶段不处理 else if 语句, 这种多个token组合起来的关键字,
         * 在语法分析阶段完成
         * else if => 遇到 else token 后, lookup next 是否是 if 
         * 如果在词法分析阶段处理, 将造成回溯(如果 else 后面不是 if,
         * 那么将回到else后面的字符位置, 重新解析), 回溯将造成效率的降低
         * */
        self.id_push_keyword_token(TokenType::Else);
    }

    fn id_kw_else_if(&mut self) {
        /*
         * 使用 elif 直接表示 else if, 提供这种关键字提升解析效率
         * */
        self.id_push_keyword_token(TokenType::ElseIf);
    }

    fn id_kw_strfmt(&mut self) {
        /*
         * strfmt""
         * strfmt<><>""
         * */
        self.id_kw_strfmt_process();
    }

    fn id_kw_func(&mut self) {
        /*
         * function
         * */
        self.id_push_keyword_token(TokenType::Function);
    }

    fn id_primeval_type(&mut self, typ: PrimevalType) {
        self.push_nooperate_token_to_token_buffer(TokenType::PrimevalType(typ));
    }

    pub fn id_process(&mut self, start_c: char) {
        let mut s = String::new();
        s.push(start_c);
        self.content.skip_next_one();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    if self.is_id(c) {
                        s.push(c);
                        self.content.skip_next_one();
                    } else {
                        break;
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            *(&mut self.content) = content;
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            break
                        }
                    }
                }
            }
        }
        match s.as_str() {
            "if" => {
                self.id_kw_if();
            },
            "else" => {
                self.id_kw_else();
            },
            "elif" => {
                self.id_kw_else_if();
            },
            "strfmt" => {
                self.id_kw_strfmt();
            },
            "func"|"fn" => {
                self.id_kw_func();
            },
            "i8"|"int8" => {
                self.id_primeval_type(PrimevalType::Int8(None));
            },
            "i16"|"int16" => {
                self.id_primeval_type(PrimevalType::Int16(None));
            },
            "i32"|"int32" => {
                self.id_primeval_type(PrimevalType::Int32(None));
            },
            "i64"|"int64" => {
                self.id_primeval_type(PrimevalType::Int64(None));
            },
            "u8"|"uint8" => {
                self.id_primeval_type(PrimevalType::Uint8(None));
            },
            "u16"|"uint16" => {
                self.id_primeval_type(PrimevalType::Uint16(None));
            },
            "u32"|"uint32" => {
                self.id_primeval_type(PrimevalType::Uint32(None));
            },
            "u64"|"uint64" => {
                self.id_primeval_type(PrimevalType::Uint64(None));
            },
            "f32"|"float32" => {
                self.id_primeval_type(PrimevalType::Float32(None));
            },
            "f64"|"float64" => {
                self.id_primeval_type(PrimevalType::Float64(None));
            },
            "string" => {
                self.id_primeval_type(PrimevalType::Str(None));
            },
            _ => {
                self.id(&s);
            }
        }
    }
}

mod strfmt;
mod id;

