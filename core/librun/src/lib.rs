use libcompile::package::{PackageContext};
use libpackage::config::{PackageConfigItem};
use std::path::Path;

pub enum Adapter {
    VirtualMachine
}

pub struct RunData<P: AsRef<Path>> {
    pub package_name: String,
    pub package_item: PackageConfigItem<P>,
    pub package_context: PackageContext
}

pub fn run<P: AsRef<Path>>(adapter: Adapter, data: RunData<P>) {
    match adapter {
        Adapter::VirtualMachine => {
            vm_adapter::run(data);
        }
    }
}

mod vm_adapter;

