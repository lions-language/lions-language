use libresult::{DescResult};
use libtype::module::Module;
use libtype::package::PackageStr;
use libgrammar::lexical::{LexicalParser, CallbackReturnStatus
    , VecU8};
use libgrammar::grammar::{ImportStmtContext
    , GrammarContext, GrammarParser};
use libcommon::consts::{ImportPrefixType};
use libcommon::ptr::{RefPtr};
use std::io::Read;
use crate::compile::{Compile, Compiler
    , InputContext, InputAttribute
    , FileType};
use crate::compile::imports_mapping::{ImportItem};
use crate::static_dispatch::{StaticVariantDispatch};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_import_stmt(&mut self, context: ImportStmtContext) -> DescResult {
        match &context.prefix {
            ImportPrefixType::Local => {
                return self.import_local(context.content, context.alias);
            },
            ImportPrefixType::Package => {
                return self.import_package(context.content, context.alias);
            },
            _ => {
                unimplemented!("{:?}", context.prefix);
            }
        }
    }

    fn import_local(&mut self, content: &str, alias: Option<String>) -> DescResult {
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
        let path_diff = match pathdiff::diff_paths(&path, &root_path) {
            Some(pd) => pd,
            None => {
                unreachable!();
            }
        };
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
        // let mut static_stream = StaticStream::new();
        // let mut static_variant_dispatch = StaticVariantDispatch::new(&mut static_stream);
        let mut static_dispatch_ptr = RefPtr::from_ref(self.static_variant_dispatch);
        let mut static_variant_dispatch = static_dispatch_ptr.as_mut::<StaticVariantDispatch>();
        /*
         * 1. 放入一个空的 module, 用于后面判断 module 语句是否存在
         * 2. 遇到 mod.lions 文件中的 module, 将 module 信息更新
         * */
        self.module_stack.push(Module::new_module_str(
                path_diff.as_path().to_str().expect("path_diff to_str error").to_string()));
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(self.module_stack, None
                    , self.cb, InputContext::new(InputAttribute::new(
                            FileType::Mod), root_path, path)
                    , static_variant_dispatch
                    , self.package_str, self.io_attr.clone()
                    , self.function_control, self.struct_control
                    , self.package_context)
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
        /*
         * module 解析完成之后, 将 module 从 stack 中 pop 出来
         * */
        let (module, _, _) = match self.module_stack.pop() {
            Some(value) => {
                value.fields_move()
            },
            None => {
                unreachable!();
            }
        };
        let (module_name, module_str) = module.fields_move();
        if self.imports_mapping.exists(&module_name) {
            return DescResult::Error(
                format!("imported \"{}\" is imported repeatedly", module_name));
        }
        let import_key = match alias {
            Some(a) => a,
            None => {
                module_name
            }
        };
        self.imports_mapping.add(import_key, ImportItem::new_with_all(
                module_str, PackageStr::Itself));
        DescResult::Success
    }

    fn import_package(&mut self, content: &str, alias: Option<String>) -> DescResult {
        /*
         * 将 content 中的第一个 段 拿出来
         * */
        let mut prefix_index = None;
        for (i, c) in content.chars().enumerate() {
            if c == ':' {
                prefix_index = Some(i);
                break;
            }
        }
        let index = match prefix_index {
            Some(index) => index,
            None => {
                return DescResult::Error(
                    format!("after package must be exist `:`"));
            }
        };
        if index == content.len() - 1 {
            /*
             * : 在最后
             * */
            return DescResult::Error(
                format!("must be speical module path after `:`"));
        }
        /*
         * 从 PackageContext 中查询
         * */
        let package_name = &content[0..index];
        let module_str = &content[index..];
        let package_buffer_ptr = match self.package_context.package_control_ref().get_ptr_clone(
            package_name) {
            Some(bp) => bp,
            None => {
                return DescResult::Error(
                    format!("package: {} is not found", package_name));
            }
        };
        let package_str = PackageStr::Third(package_buffer_ptr);
        /*
         * 写入到 import mapping 中
         * */
        /*
        let import_key = match alias {
            Some(a) => a,
            None => {
                module_name
            }
        };
        self.imports_mapping.add(import_key, module_str);
        */
        DescResult::Success
    }
}

