use libtype::AddressKey;
use super::StaticVariantDispatch;

impl StaticVariantDispatch {
    pub fn alloc(&mut self) -> AddressKey {
        let index = self.index;
        self.index += 1;
        AddressKey::new(index)
    }

    pub fn new() -> Self {
        Self {
            index: 0
        }
    }
}

