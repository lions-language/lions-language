 #[derive(Debug, Clone)]
pub enum OptCode {
    RefUint8PlusOperatorRefUint8,
    RefUint8PlusOperatorRefUint16,
    RefUint8ToStr,
    MoveUint16PlusOperatorRefUint8,
    RefUint16ToStr,
    MoveUint16ToStr,
    RefUint32PlusOperatorRefUint32,
    MoveUint32PlusOperatorRefUint8,
    RefStrPlusOperatorRefStr,
    CreateRefStrPlusOperatorRefStr,
    MoveStrPlusOperatorRefStr,
    Println
}
