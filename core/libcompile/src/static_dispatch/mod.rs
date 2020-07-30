use libcommon::ptr::RefPtr;
use crate::static_stream::StaticStream;

pub struct StaticVariantDispatch<'a> {
    index: u64,
    static_stream: &'a mut StaticStream
}

mod variant;

