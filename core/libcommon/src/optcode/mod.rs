 #[derive(Debug, Clone)]
pub enum OptCode {
    RefUint8PlusOperatorRefUint8,
    RefUint8PlusOperatorRefUint16,
    MoveUint16PlusOperatorRefUint8,
    Uint32PlusOperatorUint32
}
