use liblink::link::{Link};

pub struct VirtualMachineData {
    link: Link
}

pub enum Adapter {
    VirtualMachine(VirtualMachineData)
}

pub fn run(adapter: Adapter) {
    match adapter {
        Adapter::VirtualMachine(data) => {
            vm_adapter::run(data);
        }
    }
}

mod vm_adapter;

