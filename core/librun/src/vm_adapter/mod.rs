use libgrammar::lexical::VecU8;
use libgrammar::lexical::LexicalParser;
use libgrammar::grammar::GrammarParser;
use libgrammar::lexical::CallbackReturnStatus;
use libgrammar::grammar::GrammarContext;
use libtype::module::Module;
use libtype::instruction::{Instruction};
use libtypecontrol::function::FunctionControl;
use libstructtype::structure::{StructControl};
use libcompile::compile::{FileType, InputAttribute, InputContext, IoAttribute
    , Compiler};
use libcompile::bytecode::{self, Bytecode};
use libcompile::module::{ModuleStack, ModuleMapping};
use libcompile::define_dispatch::{FunctionDefineDispatch, BlockDefineDispatch};
use libcompile::define_stream::{DefineStream};
use libcompile::static_dispatch::{StaticVariantDispatch};
use libcompile::static_stream::{StaticStream};
use libcompile::package::{Package, PackageContext, PackageControl
    , PackageBuffer};
use libcommon::ptr::RefPtr;
use libcommon::consts;
use libcommon::exception;
use libpackage::config::{PackageConfig, PackageConfigItem};
use std::path::Path;
use std::fs;
use std::io::Read;
use crate::RunData;

struct InnerWriter {
}

impl bytecode::Writer for InnerWriter {
    fn write(&mut self, _ins: Instruction) {
    }
}

pub fn run<P: AsRef<Path>>(data: RunData<P>) {
    let name = &data.package_name;
    let item = &data.package_item;
    let package_context = &data.package_context;
    /*
     * 获取包路径, 拼接成 package_path/lib.lions
     * */
    let file: &Path = item.path.as_ref();
    let main_file = match &item.lib_path {
        Some(lib_path) => {
            file.join(lib_path).join(consts::MAIN_LIONS_NAME)
        },
        None => {
            file.join(consts::MAIN_LIONS_NAME)
        }
    };
    let mut f = match fs::File::open(&main_file) {
        Ok(f) => f,
        Err(_err) => {
            match main_file.to_str() {
                Some(s) => {
                    exception::exit(format!("read file {} error", s));
                },
                None => {
                    exception::exit(format!("read file {:?} error", main_file));
                }
            }
            panic!("");
        }
    };
    let path_buf = Path::new(&main_file).parent().expect("should not happend").to_path_buf();
    let io_attr = IoAttribute::new_with_all(item.read_once_max);
    let io_attr_clone = io_attr.clone();
    let file_name = match file.to_str() {
        Some(s) => s.to_string(),
        None => {
            exception::exit("the path is illegal, please use utf8 encoding path");
            panic!("");
        }
    };
    let lexical_parser = LexicalParser::new(file_name, || -> CallbackReturnStatus {
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
    let mut ds = DefineStream::new();
    let ds_ptr = RefPtr::from_ref::<DefineStream>(&ds);
    let mut func_ds = ds_ptr.clone();
    let mut fdd = FunctionDefineDispatch::new(func_ds.as_mut::<DefineStream>());
    let mut bdd = BlockDefineDispatch::new(&mut ds);
    let mut static_stream = StaticStream::new();
    let mut static_variant_dispatch = StaticVariantDispatch::new(&mut static_stream);
    let package_str = name;
    let mut inner_writer = InnerWriter{};
    let module = Module::new(String::from(consts::LIB_NAME), String::from(consts::LIB_NAME));
    let mut module_stack = ModuleStack::new();
    let mut function_control = FunctionControl::new();
    let mut struct_control = StructControl::new();
    let mut module_mapping = ModuleMapping::new();
    let mut bytecode = Bytecode::new(
                &mut inner_writer
                , &mut fdd
                , &mut bdd);
    let mut grammar_context = GrammarContext{
        cb: Compiler::new(
            &mut module_stack, Some(module)
            , &mut bytecode
            , InputContext::new(InputAttribute::new(FileType::Lib)
                , path_buf.clone(), path_buf)
            , &mut static_variant_dispatch
            , package_str, io_attr_clone
            , &mut function_control
            , &mut struct_control
            , package_context
            , &mut module_mapping
        )
    };
    let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
    grammar_parser.parser();
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;
    use libpackage::control::Control;

    #[test]
    fn run_test() {
        let package = Package::<PathBuf>::new();
        let package_control = PackageControl::new();
        let package_context = PackageContext::new(&package, &package_control);
        let config_item = PackageConfigItem::<PathBuf>::new(
            true, 1, Path::new(".").to_path_buf(), None);
        let mut control = Control::new();
        let run_data = RunData {
            package_name: String::from("main"),
            package_item: config_item,
            package_context: package_context
        };
        run::<PathBuf>(run_data);
    }
}

