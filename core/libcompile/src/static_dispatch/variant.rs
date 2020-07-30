use libtype::AddressKey;
use libtype::Data;
use libcommon::ptr::RefPtr;
use super::StaticVariantDispatch;
use crate::static_stream::StaticStream;

impl<'a> StaticVariantDispatch<'a> {
    pub fn alloc(&mut self, data: Data) -> AddressKey {
        let index = self.index;
        self.static_stream.push(data);
        self.index += 1;
        AddressKey::new(index)
    }

    pub fn new(static_stream: &'a mut StaticStream) -> Self {
        Self {
            index: 0,
            static_stream: static_stream
        }
    }
}

