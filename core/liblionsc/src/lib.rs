use libcompile::package::{PackageContext};
use libpackage::config::{PackageConfigItem};
use liblink::link::Link;
use std::path::Path;

pub enum Adapter {
    VirtualMachine
}

pub struct CompileData<P: AsRef<Path>> {
    pub package_name: String,
    pub package_item: PackageConfigItem<P>,
    pub package_context: PackageContext
}

pub struct VMCompileResult {
    pub link: Link
}

pub enum CompileResult {
    VirtualMachine(VMCompileResult)
}

pub fn compile_main<P: AsRef<Path>>(adapter: Adapter, data: CompileData<P>) -> CompileResult {
    match adapter {
        Adapter::VirtualMachine => {
            vm_adapter::compile_main(data)
        }
    }
}

mod vm_adapter;

