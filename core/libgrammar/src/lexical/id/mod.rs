use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType, TokenData};
use id::IdToken;
use crate::lexical::boolean::true_token::TrueToken;
use crate::grammar::Grammar;
use libtype::primeval::{PrimevalType, PrimevalData
    , boolean::Boolean, boolean::BooleanValue};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn id_push_keyword_token(&mut self, token_type: TokenType) {
        self.push_nooperate_nodata_token_to_token_buffer(token_type);
    }

    fn id(&mut self, s: &String) {
        /*
         * 存入 context
         * */
        let context = self.build_token_context(TokenType::Id, TokenData::Id(s.to_string()));
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

    fn id_kw_for(&mut self) {
        self.id_push_keyword_token(TokenType::For);
    }

    fn id_kw_while(&mut self) {
        self.id_push_keyword_token(TokenType::While);
    }

    fn id_kw_loop(&mut self) {
        self.id_push_keyword_token(TokenType::Loop);
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

    fn id_kw_let(&mut self) {
        /*
         * let
         * */
        self.id_push_keyword_token(TokenType::Let);
    }

    fn id_kw_var(&mut self) {
        /*
         * var
         * */
        self.id_push_keyword_token(TokenType::Var);
    }

    fn id_kw_return(&mut self) {
        /*
         * return
         * */
        self.id_push_keyword_token(TokenType::Return);
    }

    fn id_kw_struct(&mut self) {
        /*
         * struct
         * */
        self.id_push_keyword_token(TokenType::Structure);
    }

    fn id_kw_interface(&mut self) {
        self.id_push_keyword_token(TokenType::Interface);
    }

    fn id_kw_break(&mut self) {
        self.id_push_keyword_token(TokenType::Break);
    }

    fn id_kw_continue(&mut self) {
        self.id_push_keyword_token(TokenType::Continue);
    }

    fn id_kw_is(&mut self) {
        /*
         * 定义于 lexical/is_opt/mod.rs
         * */
        self.build_is_opt();
    }

    fn id_kw_impl(&mut self) {
        /*
         * 定义于 lexical/impl_opd/mod.rs
         * */
        self.build_impl_opd();
    }

    fn id_kw_import(&mut self) {
        /*
         * import
         * */
        self.id_push_keyword_token(TokenType::Import);
    }

    fn id_kw_relmod(&mut self) {
        /*
         * relmod
         * */
        self.id_push_keyword_token(TokenType::Relmod);
    }

    fn id_kw_module(&mut self) {
        /*
         * module
         * */
        self.id_push_keyword_token(TokenType::Module);
    }

    fn id_kw_use(&mut self) {
        /*
         * use
         * */
        self.id_push_keyword_token(TokenType::Use);
    }

    fn id_kw_true(&mut self) {
        /*
         * true
         * */
        let context = self.build_token_context(TokenType::True
            , TokenData::Const(PrimevalData::Boolean(Boolean::new(BooleanValue::True))));
        self.push_to_token_buffer(TrueToken::new(context));
    }

    fn id_kw_false(&mut self) {
        /*
         * false
         * */
        let context = self.build_token_context(TokenType::False
            , TokenData::Const(PrimevalData::Boolean(Boolean::new(BooleanValue::False))));
        self.push_to_token_buffer(TrueToken::new(context));
    }

    fn id_kw_as(&mut self) {
        /*
         * as
         * */
        self.id_push_keyword_token(TokenType::As);
    }

    fn id_primeval_type(&mut self, typ: PrimevalType) {
        self.push_nooperate_nodata_token_to_token_buffer(TokenType::PrimevalType(typ));
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
            "for" => {
                self.id_kw_for();
            },
            "while" => {
                self.id_kw_while();
            },
            "loop" => {
                self.id_kw_loop();
            },
            "strfmt" => {
                self.id_kw_strfmt();
            },
            "func"|"fn" => {
                self.id_kw_func();
            },
            "let" => {
                self.id_kw_let();
            },
            "var" => {
                self.id_kw_var();
            },
            "return" => {
                self.id_kw_return();
            },
            "struct" => {
                self.id_kw_struct();
            },
            "interface" => {
                self.id_kw_interface();
            },
            "true" => {
                self.id_kw_true();
            },
            "false" => {
                self.id_kw_false();
            },
            "import" => {
                self.id_kw_import();
            },
            "relmod" => {
                self.id_kw_relmod();
            },
            "module" => {
                self.id_kw_module();
            },
            "use" => {
                self.id_kw_use();
            },
            "as" => {
                self.id_kw_as();
            },
            "break" => {
                self.id_kw_break();
            },
            "continue" => {
                self.id_kw_continue();
            },
            "is" => {
                self.id_kw_is();
            },
            "impl" => {
                self.id_kw_impl();
            },
            _ => {
                self.id(&s);
            }
        }
    }
}

mod strfmt;
mod id;

            /*
            "i8"|"int8" => {
                self.id_primeval_type(PrimevalType::Int8);
            },
            "i16"|"int16" => {
                self.id_primeval_type(PrimevalType::Int16);
            },
            "i32"|"int32" => {
                self.id_primeval_type(PrimevalType::Int32);
            },
            "i64"|"int64" => {
                self.id_primeval_type(PrimevalType::Int64);
            },
            "u8"|"uint8" => {
                self.id_primeval_type(PrimevalType::Uint8);
            },
            "u16"|"uint16" => {
                self.id_primeval_type(PrimevalType::Uint16);
            },
            "u32"|"uint32" => {
                self.id_primeval_type(PrimevalType::Uint32);
            },
            "u64"|"uint64" => {
                self.id_primeval_type(PrimevalType::Uint64);
            },
            "f32"|"float32" => {
                self.id_primeval_type(PrimevalType::Float32);
            },
            "f64"|"float64" => {
                self.id_primeval_type(PrimevalType::Float64);
            },
            "string" => {
                self.id_primeval_type(PrimevalType::Str);
            },
            */

