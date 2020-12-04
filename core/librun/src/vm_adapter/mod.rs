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
use libcommon::ptr::RefPtr;
use liblink::define::LinkDefine;
use liblink::statics::LinkStatic;
use libvm::vm::VirtualMachine;
use crate::VirtualMachineData;

pub fn run(mut data: VirtualMachineData) {
    let entrance = data.link.call_main_instruction().clone();
    /*
     * 如果存在编译后的文件, 使用 LinkDefine 的读取功能 从文件中读取后实例化 LinkDefine
     * */
    let mut virtual_machine = VirtualMachine::new(
        RefPtr::from_ref::<LinkDefine>(data.link.link_define())
        , RefPtr::from_ref::<LinkStatic>(data.link.link_static()));
    virtual_machine.run(entrance);
}

