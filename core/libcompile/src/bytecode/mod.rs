use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddrValue};
use libtype::function::{FunctionDefine, Function
    , FunctionParamDataItem
    , FunctionReturn
    , FunctionReturnDataAttr
    , FunctionStatement};
use libtype::instruction::{Instruction, CallPrimevalFunction
    , CallFunction, StaticVariant
    , LoadStack, OwnershipMove
    , AddressBind, ReturnStmt
    , Jump, RemoveOwnership
    , CallSelfFunction
    , AddRefParamAddr, CallPrimevalFunctionParamContext
    , IfStmt, BlockDefine, DeleteData
    , WhileStmt, ConditionStmt};
use libgrammar::grammar::{FunctionDefineContext
    , BlockDefineContext};
use crate::compile::{StaticContext, CallFunctionContext
    , FunctionNamedStmtContext, Compile
    , LoadStackContext, OwnershipMoveContext
    , AddressBindContext, ReturnStmtContext};
use define_stack::DefineStack;
use crate::define_dispatch::{FunctionDefineDispatch
    , BlockDefineDispatch
    , function::FunctionStatementObject};
use crate::define::{DefineObject};

pub trait Writer {
    fn write(&mut self, _: Instruction) {
    }
}

pub struct Bytecode<'a, 'b, F: Writer> {
    writer: &'a mut F,
    define_stack: DefineStack,
    func_define_dispatch: &'a mut FunctionDefineDispatch<'b>,
    block_define_dispatch: &'a mut BlockDefineDispatch<'b>
}

impl<'a, 'b, F: Writer> Compile for Bytecode<'a, 'b, F> {
    fn const_number(&mut self, context: StaticContext) {
        let instruction = Instruction::ReadStaticVariant(StaticVariant{
            package_str: context.package_str,
            addr: context.addr,
            static_addr: context.static_addr
        });
        self.write(instruction);
    }

    fn const_string(&mut self, context: StaticContext) {
        let instruction = Instruction::ReadStaticVariant(StaticVariant{
            package_str: context.package_str,
            addr: context.addr,
            static_addr: context.static_addr
        });
        self.write(instruction);
    }
    
    fn load_stack(&mut self, context: LoadStackContext) {
        let (addr, data) = context.fields_move();
        // println!("{:?}", addr);
        self.write(Instruction::LoadStack(LoadStack::new_with_all(
                    addr, data)));
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        match &context.func_define {
            FunctionDefine::Optcode(def) => {
                let instruction = Instruction::CallPrimevalFunction(
                    CallPrimevalFunction{
                        opt: def.optcode.clone(),
                        param_addrs: context.param_addrs,
                        param_context: context.param_context,
                        call_param_len: context.call_param_len,
                        return_data: context.return_data
                    }
                    );
                self.write(instruction);
            },
            FunctionDefine::Address(addr) => {
                let instruction = Instruction::CallFunction(
                    CallFunction{
                        package_str: context.package_str,
                        define_addr: addr.addr_ref().clone(),
                        return_data: context.return_data
                    }
                );
                self.write(instruction);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn call_self_function(&mut self, context: CallSelfFunction) {
        self.write(Instruction::CallSelfFunction(context));
    }

    fn function_define_start(&mut self) {
    }

    fn function_named_stmt(&mut self, context: FunctionNamedStmtContext
        , define_context: &mut FunctionDefineContext) -> RefPtr {
        let (statement_ptr, define_obj) = self.func_define_dispatch.alloc_define(context);
        *define_context.define_obj_mut() = define_obj.original().clone();
        self.define_stack.enter(define_obj);
        statement_ptr
    }

    fn function_push_param_to_statement(&mut self
        , item: FunctionParamDataItem
        , define_context: &FunctionDefineContext) {
        // let ds = self.define_stack.back_mut_unchecked();
        let mut ds = DefineObject::new(define_context.define_obj_clone());
        self.func_define_dispatch.push_function_param_to_statement(&mut ds, item);
    }

    fn function_set_return_to_statement(&mut self
        , item: FunctionReturn
        , define_context: &FunctionDefineContext) {
        // let ds = self.define_stack.back_mut_unchecked();
        let mut ds = DefineObject::new(define_context.define_obj_clone());
        self.func_define_dispatch.set_function_return_to_statement(&mut ds, item);
    }

    fn update_func_return_data_addr(&mut self, attr: FunctionReturnDataAttr
        , define_obj: DefineObject) {
        // let ds = self.define_stack.back_mut_unchecked();
        let mut ds = define_obj;
        self.func_define_dispatch.update_func_return_data_attr(&mut ds, attr);
    }

    fn current_function_statement(&self
        , define_obj: DefineObject) -> Option<FunctionStatementObject> {
        self.func_define_dispatch.current_function_statement(&define_obj)
    }

    fn current_function_addr_value(&self
        , define_obj: DefineObject) -> FunctionAddrValue {
        self.func_define_dispatch.current_function_addr_value(&define_obj)
    }

    fn function_define_end(&mut self
        , define_context: &FunctionDefineContext) -> Function {
        self.define_stack.leave();
        let ds = DefineObject::new(define_context.define_obj_clone());
        self.func_define_dispatch.finish_define(&ds)
    }

    fn enter_block_define(&mut self, define_context: &mut BlockDefineContext) {
        let define_obj = self.block_define_dispatch.alloc_define();
        *define_context.define_obj_mut() = define_obj.original().clone();
        self.define_stack.enter(define_obj);
    }

    fn current_block_addr_value(&self, define_obj: DefineObject) -> FunctionAddrValue {
        self.block_define_dispatch.current_block_addr_value(&define_obj)
    }

    fn leave_block_define(&mut self, define_obj: DefineObject) -> FunctionAddrValue {
        self.define_stack.leave();
        self.block_define_dispatch.finish_define(&define_obj)
    }

    fn ownership_move(&mut self, context: OwnershipMoveContext) {
        // println!("{:?}", &context);
        // println!("ownership move");
        let (dst_addr, src_addr) = context.fields_move();
        self.write(Instruction::OwnershipMove(OwnershipMove::new_with_all(
                    dst_addr, src_addr)));
    }

    fn address_bind(&mut self, context: AddressBindContext) {
        let (src_addr, dst_addr) = context.fields_move();
        self.write(Instruction::AddressBind(AddressBind::new_with_all(
            src_addr, dst_addr)));
    }

    fn return_stmt(&mut self, context: ReturnStmtContext) {
        let (scope, addr_value) = context.fields_move();
        self.write(Instruction::ReturnStmt(ReturnStmt::new_with_all(
                    scope, addr_value)));
    }

    fn if_stmt(&mut self, context: IfStmt) {
        self.write(Instruction::IfStmt(context));
    }

    fn condition_stmt(&mut self, context: ConditionStmt) {
        self.write(Instruction::ConditionStmt(context));
    }

    fn while_stmt(&mut self, context: WhileStmt) {
        self.write(Instruction::WhileStmt(context));
    }

    fn jump(&mut self, context: Jump) -> usize {
        self.write(Instruction::Jump(context));
        self.current_index()
    }

    fn current_index(&self) -> usize {
        if self.define_stack.is_empty() {
            0
        } else {
            self.define_stack.current_index()
        }
    }

    fn update_instructure_by_index(&mut self, index: usize, ins: Instruction) {
        if self.define_stack.is_empty() {
            panic!("should not happend");
        } else {
            self.define_stack.update_instructure_by_index(index, ins);
        }
    }

    fn get_current_instructure_ptr(&self, index: usize) -> RefPtr {
        if self.define_stack.is_empty() {
            panic!("should not happend");
        } else {
            self.define_stack.get_current_instructure_ptr(index)
        }
    }

    fn set_jump(&mut self, index: usize, jump: Jump) {
        if self.define_stack.is_empty() {
        } else {
            self.define_stack.set_jump(index, jump);
        }
    }

    fn enter_scope(&mut self) {
        self.write(Instruction::EnterScope);
    }

    fn leave_scope(&mut self) {
        self.write(Instruction::LeaveScope);
    }

    fn remove_ownership(&mut self, context: RemoveOwnership) {
        self.write(Instruction::RemoveOwnership(context));
    }

    fn add_ref_param_addr(&mut self, context: AddRefParamAddr) {
        self.write(Instruction::AddRefParamAddr(context));
    }

    fn execute_block(&mut self, context: BlockDefine) {
        self.write(Instruction::ExecuteBlock(context));
    }

    fn delete_data(&mut self, context: DeleteData) {
        self.write(Instruction::DeleteData(context));
    }
}

impl<'a, 'b, F: Writer> Bytecode<'a, 'b, F> {
    fn write(&mut self, instruction: Instruction) {
        /*
         * NOTE: 决定将字节码向哪个输出流写
         * */
        if self.define_stack.is_empty() {
            self.writer.write(instruction);
        } else {
            self.define_stack.write(instruction);
        }
    }

    pub fn new(writer: &'a mut F, func_define_dispatch: &'a mut FunctionDefineDispatch<'b>
        , block_define_dispatch: &'a mut BlockDefineDispatch<'b>) -> Self {
        Self {
            writer: writer,
            define_stack: DefineStack::new(),
            func_define_dispatch: func_define_dispatch,
            block_define_dispatch: block_define_dispatch
        }
    }
}

mod define_stack;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use libtypecontrol::function::FunctionControl;
    use libstructtype::structure::{StructControl};
    use crate::compile::{Compiler, InputContext, InputAttribute, FileType
        , IoAttribute};
    use crate::module::{ModuleStack, ModuleMapping};
    use crate::address::{PackageIndex};
    use crate::define_stream::DefineStream;
    use crate::static_dispatch::{StaticVariantDispatch};
    use crate::static_stream::{StaticStream};
    use crate::package::{Package, PackageContext, PackageControl};
    use super::*;

    use std::fs;
    use std::io::Read;
    use std::path::Path;

    struct TestWriter {
    }

    impl Writer for TestWriter {
    }

    #[test]
    fn grammar_parser_test() {
        let file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(_err) => {
                panic!("read file error");
            }
        };
        let path_buf = Path::new(&file).parent().expect("should not happend").to_path_buf();
        let io_attr = IoAttribute::new_with_all(1);
        let io_attr_clone = io_attr.clone();
        let lexical_parser = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
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
        let mut ds_ptr = RefPtr::from_ref::<DefineStream>(&ds);
        let mut func_ds = ds_ptr.clone();
        let mut fdd = FunctionDefineDispatch::new(func_ds.as_mut::<DefineStream>());
        let mut bdd = BlockDefineDispatch::new(&mut ds);
        let mut static_stream = StaticStream::new();
        let mut static_variant_dispatch = StaticVariantDispatch::new(&mut static_stream);
        let mut package_index = PackageIndex::new();
        let package_str = String::from("test");
        let mut test_writer = TestWriter{};
        let module = Module::new(String::from("main"), String::from("main"));
        let mut module_stack = ModuleStack::new();
        let mut function_control = FunctionControl::new();
        let mut struct_control = StructControl::new();
        let mut bytecode = Bytecode::new(
                    &mut test_writer
                    , &mut fdd
                    , &mut bdd);
        let package = Package::<String>::new();
        let package_control = PackageControl::new();
        let package_context = PackageContext::new(&package, &package_control);
        let mut module_mapping = ModuleMapping::new();
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(
                &mut module_stack, Some(module),
                &mut bytecode,
                InputContext::new(InputAttribute::new(FileType::Main)
                    , path_buf.clone(), path_buf),
                &mut static_variant_dispatch,
                &package_str, io_attr_clone,
                &mut function_control,
                &mut struct_control,
                &package_context,
                &mut module_mapping
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
