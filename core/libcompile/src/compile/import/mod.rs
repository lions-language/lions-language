use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::lexical::{LexicalParser, CallbackReturnStatus
    , IoAttribute, VecU8};
use libgrammar::grammar::{ImportStmtContext
    , GrammarContext, GrammarParser};
use libcommon::consts::{ImportPrefixType};
use libtype::module::Module;
use std::path::Path;
use std::io::Read;
use crate::compile::{Compile, Compiler
    , InputContext, InputAttribute
    , FileType};
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
        let path = Path::new(content);
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
        if !path.join(libcommon::consts::MOD_LIONS_NAME).as_path().exists() {
            return DescResult::Error(
                format!("{} does not exist in the path of import"
                    , libcommon::consts::MOD_LIONS_NAME));
        }
        /*
         * 解析 main.lions
         * */
        let file = String::from("main.lions");
        let mut f = match std::fs::File::open(&file) {
            Ok(f) => f,
            Err(_err) => {
                panic!("read file error");
            }
        };
        let io_attr = IoAttribute::new_with_all(1);
        let lexical_parser = LexicalParser::new(file.clone(), io_attr.clone()
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
        let package_str = String::from("test");
        let module = Module::new(String::from("main"));
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(&module
                    , self.cb, InputContext::new(InputAttribute::new(
                            FileType::Mod))
                    , &mut static_variant_dispatch
                    , &package_str)
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
        DescResult::Success
    }
}

