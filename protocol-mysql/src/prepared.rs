//! Decode prepared-statement execution using connection-local parameter metadata.
use crate::response::parse_binary_value;
use crate::{
    MysqlPacket,
    model::{BoundParamType, MysqlValue, PreparedStatement},
    values::*,
};
use std::collections::HashMap;

#[derive(Debug)]
pub struct ParsedStmtExecute {
    pub statement_id: u32,
    pub params: Option<Vec<MysqlValue>>,
    pub param_types: Option<Vec<BoundParamType>>,
    pub warnings: Vec<String>,
}

pub fn parse_stmt_execute(
    packet: &MysqlPacket,
    statements: &HashMap<u32, PreparedStatement>,
) -> ParsedStmtExecute {
    let Some(statement_id) = read_u32_le(&packet.payload, 1) else {
        return ParsedStmtExecute {
            statement_id: 0,
            params: None,
            param_types: None,
            warnings: vec!["COM_STMT_EXECUTE packet missing statement id".to_string()],
        };
    };
    let Some(statement) = statements.get(&statement_id) else {
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings: Vec::new(),
        };
    };
    let param_count = statement.param_count;
    if param_count == 0 {
        return ParsedStmtExecute {
            statement_id,
            params: Some(Vec::new()),
            param_types: Some(Vec::new()),
            warnings: Vec::new(),
        };
    }
    let mut warnings = Vec::new();
    if packet.payload.len() < 11 {
        warnings.push("COM_STMT_EXECUTE packet too short for parameter metadata".to_string());
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings,
        };
    }

    let bitmap_offset = 10;
    let bitmap_len = param_count.div_ceil(8);
    let Some(null_bitmap) = packet
        .payload
        .get(bitmap_offset..bitmap_offset + bitmap_len)
    else {
        warnings.push("COM_STMT_EXECUTE packet missing parameter null bitmap".to_string());
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings,
        };
    };
    let mut offset = bitmap_offset + bitmap_len;
    let Some(new_params_bound_flag) = packet.payload.get(offset).copied() else {
        warnings.push("COM_STMT_EXECUTE packet missing new-params-bound flag".to_string());
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types: None,
            warnings,
        };
    };
    offset += 1;

    let param_types = if new_params_bound_flag == 1 {
        let mut param_types = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            let Some(type_code) = packet.payload.get(offset).copied() else {
                warnings.push("COM_STMT_EXECUTE packet ended inside parameter types".to_string());
                return ParsedStmtExecute {
                    statement_id,
                    params: None,
                    param_types: None,
                    warnings,
                };
            };
            let Some(flags) = packet.payload.get(offset + 1).copied() else {
                warnings.push("COM_STMT_EXECUTE packet ended inside parameter flags".to_string());
                return ParsedStmtExecute {
                    statement_id,
                    params: None,
                    param_types: None,
                    warnings,
                };
            };
            param_types.push(BoundParamType {
                type_code,
                unsigned: flags & 0x80 != 0,
            });
            offset += 2;
        }
        Some(param_types)
    } else if statement.last_param_types.len() == param_count {
        Some(statement.last_param_types.clone())
    } else {
        warnings.push(format!(
            "COM_STMT_EXECUTE for statement {statement_id} reused parameter types before replay captured them"
        ));
        None
    };

    let Some(types) = param_types.as_ref() else {
        return ParsedStmtExecute {
            statement_id,
            params: None,
            param_types,
            warnings,
        };
    };
    let mut params = Vec::with_capacity(param_count);
    for (index, param_type) in types.iter().enumerate() {
        if null_bitmap_bit(null_bitmap, index) {
            params.push(mysql_null());
            continue;
        }
        match parse_binary_value(
            &packet.payload,
            offset,
            param_type.type_code,
            param_type.unsigned,
            false,
        ) {
            Some((value, next)) => {
                params.push(value);
                offset = next;
            }
            None => {
                warnings.push(format!(
                    "failed to parse COM_STMT_EXECUTE parameter {index}"
                ));
                break;
            }
        }
    }

    ParsedStmtExecute {
        statement_id,
        params: Some(params),
        param_types,
        warnings,
    }
}
