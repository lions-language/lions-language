use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::lexical::{LexicalParser, CallbackReturnStatus
    , VecU8};
use libgrammar::grammar::{ImportStmtContext
    , GrammarContext, GrammarParser};
use libcommon::consts::{ImportPrefixType};
use libtype::module::Module;
use std::path::Path;
use std::io::Read;
use crate::compile::{Compile, Compiler
    , InputContext, InputAttribute
    , FileType, IoAttribute};
use crate::address::PackageIndex;
use crate::static_stream::StaticStream;
use crate::static_dispatch::{StaticVariantDispatch};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_import_stmt(&mut self, context: ImportStmtContext) -> DescResult {
        match &context.prefix {
            ImportPrefixType::Local => {
                return self.import_local(context.content);
            },
            _ => {
                unimplemented!("{:?}", context.prefix);
            }
        }
    }

    fn import_local(&mut self, content: &str) -> DescResult {
        /*
         * 检测路径是否是目录
         * */
        let root_path = self.input_context.root_path.clone();
        let path = root_path.join(content);
        // let path_buf = path.to_path_buf();
        // let path = Path::new(content);
        if !path.exists() {
            return DescResult::Error(
                format!("import path: {:?} is not found", content));
        }
        if !path.is_dir() {
            return DescResult::Error(
                format!("import path: {:?} is not dir", content));
        }
        /*
         * 检测路径是否包含 mod.lions
         * */
        let mod_path = path.join(libcommon::consts::MOD_LIONS_NAME);
        if !mod_path.as_path().exists() {
            return DescResult::Error(
                format!("{} does not exist in the path of import"
                    , libcommon::consts::MOD_LIONS_NAME));
        }
        /*
         * 解析 mod.lions
         * */
        let mod_path_str = match mod_path.as_path().to_str() {
            Some(s) => s,
            None => {
                return DescResult::Error(
                    format!("mod.lions path is not utf8"));
            }
        };
        let mut f = match std::fs::File::open(mod_path_str) {
            Ok(f) => f,
            Err(_err) => {
                return DescResult::Error(
                    format!("read file: {:?} error", mod_path_str));
            }
        };
        let io_attr = self.io_attr.clone();
        let lexical_parser = LexicalParser::new(mod_path_str.to_string()
            , || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let f_ref = f.by_ref();
            match f_ref.take(io_attr.read_once_max_clone() as u64).read_to_end(&mut v) {
                Ok(len) => {
                    if len == 0 {
                        return CallbackReturnStatus::End;
                    } else {
                        return CallbackReturnStatus::Continue(VecU8::from_vec_u8(v));
                    }
                },
                Err(_) => {
                    return CallbackReturnStatus::End;
                }
            }
        });
        let mut static_stream = StaticStream::new();
        let mut static_variant_dispatch = StaticVariantDispatch::new(&mut static_stream);
        /*
         * 1. 放入一个空的 module, 用于后面判断 module 语句是否存在
         * 2. 遇到 mod.lions 文件中的 module, 将 module 信息更新
         * */
        self.module_stack.push_null();
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(self.module_stack, None
                    , self.cb, InputContext::new(InputAttribute::new(
                            FileType::Mod), root_path, path)
                    , &mut static_variant_dispatch
                    , self.package_str, self.io_attr.clone())
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
        DescResult::Success
    }
}

