use libtype::AddressKey;
use super::StaticVariantDispatch;

impl StaticVariantDispatch {
    pub fn alloc(&mut self) -> usize {
        let index = self.index;
        self.index += 1;
        index
    }

    pub fn new() -> Self {
        Self {
            index: 0
        }
    }
}

