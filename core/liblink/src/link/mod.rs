use libcompile::bytecode::{self};
use libtype::instruction::{Instruction};
use libcommon::ptr::RefPtr;
use crate::define::{LinkDefine};
use crate::statics::{LinkStatic};

pub struct Link {
    link_define: LinkDefine,
    call_main_instruction: Instruction
}

impl bytecode::Writer for Link {
    fn write(&mut self, mut instruction: Instruction) {
        // println!("{:?}", instruction);
        /*
         * 这里只会进一次, main入口
         * 第一个指令一定是调用入口函数, 所以交给 define 处理
         * */
        self.link_define.start(&mut instruction);
        /*
         * 链接静态量
         * */
        *&mut self.call_main_instruction = instruction;
    }
}


impl Link {
    pub fn link_define(&mut self) -> &mut LinkDefine {
        &mut self.link_define
    }

    pub fn link_static(&mut self) -> &mut LinkStatic {
        self.link_define.link_static()
    }

    pub fn call_main_instruction(&self) -> &Instruction {
        &self.call_main_instruction
    }

    pub fn new(define_stream: RefPtr
        , static_stream: RefPtr) -> Self {
        Self {
            link_define: LinkDefine::new(define_stream
                             , static_stream),
            call_main_instruction: Instruction::Invalid
        }
    }
}

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use libcompile::compile::{FileType, Compile, Compiler
    , InputAttribute, InputContext};
    use libcompile::address::PackageIndex;
    use libcompile::bytecode::{self, Bytecode};
    use libcompile::define_stream::{DefineStream};
    use libcompile::define_dispatch::{FunctionDefineDispatch};
    use libcompile::static_dispatch::{StaticVariantDispatch};
    use libcompile::static_stream::{StaticStream};
    use super::*;

    use std::fs;
    use std::io::Read;

    #[test]
    // #[ignore]
    fn link_test() {
        let file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(_err) => {
                panic!("read file error");
            }
        };
        let lexical_parser = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let f_ref = f.by_ref();
            match f_ref.take(1).read_to_end(&mut v) {
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
        let mut ds = DefineStream::new();
        let mut ss = StaticStream::new();
        let ds_ptr = RefPtr::from_ref::<DefineStream>(&ds);
        let ss_ptr = RefPtr::from_ref::<StaticStream>(&ss);
        let mut fdd = FunctionDefineDispatch::new(&mut ds);
        let mut package_index = PackageIndex::new();
        let mut static_variant_dispatch = StaticVariantDispatch::new(
            &mut ss);
        let package_str = String::from("test");
        let mut link = Link::new(ds_ptr
            , ss_ptr);
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(
                    Module::new(String::from("main"))
                    , Bytecode::new(
                        &mut link
                        , &mut fdd)
                    , InputContext::new(InputAttribute::new(
                            FileType::Main))
                    , &mut package_index
                    , &mut static_variant_dispatch
                    , &package_str)
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
