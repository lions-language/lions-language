 #[derive(Debug, Clone)]
pub enum OptCode {
    RefUint8PlusOperatorRefUint8,
    RefUint8PlusOperatorRefUint16,
    MoveUint16PlusOperatorRefUint8,
    RefUint32PlusOperatorRefUint32,
    MoveUint32PlusOperatorRefUint8,
    Println
}
