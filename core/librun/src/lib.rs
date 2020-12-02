pub enum Adapter {
    VirtualMachine
}

pub struct RunData {
}

pub fn run(adapter: Adapter, data: RunData) {
    match adapter {
        Adapter::VirtualMachine => {
            vm_adapter::run(data);
        }
    }
}

mod vm_adapter;

