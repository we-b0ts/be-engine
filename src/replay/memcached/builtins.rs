use crate::memcached::MemcachedRequest;

const GET: u8 = 0x00;
const GETQ: u8 = 0x09;
const GETK: u8 = 0x0c;
const GETKQ: u8 = 0x0d;

pub(super) fn memcached_is_unsupported(request: &MemcachedRequest) -> bool {
    matches!(
        request.command.as_str(),
        "mg" | "ms"
            | "md"
            | "ma"
            | "me"
            | "mn"
            | "sasl_list_mechs"
            | "sasl_auth"
            | "sasl_step"
            | "unknown"
    )
}

pub(super) fn binary_get_opcodes_match(recorded: Option<u8>, requested: Option<u8>) -> bool {
    recorded == requested
        || matches!(
            (recorded, requested),
            (
                Some(GET | GETQ | GETK | GETKQ),
                Some(GET | GETQ | GETK | GETKQ)
            )
        )
}

pub(super) fn adapt_binary_get_responses(
    responses: &mut Vec<Vec<u8>>,
    requested_opcode: u8,
    requested_opaque: u32,
    requested_key: Option<&[u8]>,
    recorded_no_response: bool,
) -> Result<(), &'static str> {
    if !is_binary_get_opcode(requested_opcode) {
        rewrite_opaque(responses, requested_opaque);
        return Ok(());
    }
    if responses.is_empty() && recorded_no_response && !is_quiet_get_opcode(requested_opcode) {
        responses.push(binary_get_miss(requested_opcode, requested_opaque));
        return Ok(());
    }

    for response in responses.iter_mut() {
        adapt_binary_get_response(response, requested_opcode, requested_key)?;
        response[12..16].copy_from_slice(&requested_opaque.to_be_bytes());
    }
    if is_quiet_get_opcode(requested_opcode)
        && responses
            .first()
            .is_some_and(|response| response_status(response) != Some(0))
    {
        responses.clear();
    }
    Ok(())
}

pub(super) fn binary_error(opcode: u8, opaque: u32) -> Vec<u8> {
    let message = b"no recorded dependency matched";
    let mut response = vec![0_u8; 24];
    response[0] = 0x81;
    response[1] = opcode;
    response[6..8].copy_from_slice(&0x0084_u16.to_be_bytes());
    response[8..12].copy_from_slice(&(message.len() as u32).to_be_bytes());
    response[12..16].copy_from_slice(&opaque.to_be_bytes());
    response.extend_from_slice(message);
    response
}

fn adapt_binary_get_response(
    response: &mut Vec<u8>,
    requested_opcode: u8,
    requested_key: Option<&[u8]>,
) -> Result<(), &'static str> {
    if response.len() < 24 || response[0] != 0x81 {
        return Err("recorded Memcached binary response has an invalid header");
    }
    let body_len = usize::try_from(u32::from_be_bytes(
        response[8..12]
            .try_into()
            .expect("validated Memcached response header"),
    ))
    .map_err(|_| "recorded Memcached response body length is not representable")?;
    if response.len() < 24 + body_len {
        return Err("recorded Memcached binary response body is truncated");
    }
    response[1] = requested_opcode;
    if response_status(response) != Some(0) {
        return Ok(());
    }

    let extras_len = usize::from(response[4]);
    let recorded_key_len = usize::from(u16::from_be_bytes(
        response[2..4]
            .try_into()
            .expect("validated Memcached response header"),
    ));
    if extras_len + recorded_key_len > body_len {
        return Err("recorded Memcached binary response sections are invalid");
    }
    let key_start = 24 + extras_len;
    let key_end = key_start + recorded_key_len;
    if get_response_includes_key(requested_opcode) {
        if recorded_key_len == 0 {
            let key = requested_key.ok_or("Memcached GETK request is missing its key")?;
            let new_key_len =
                u16::try_from(key.len()).map_err(|_| "Memcached GETK key is too large")?;
            let new_body_len = body_len
                .checked_add(key.len())
                .ok_or("Memcached GETK response body length overflow")?;
            let new_body_len = u32::try_from(new_body_len)
                .map_err(|_| "Memcached GETK response body is too large")?;
            response.splice(key_start..key_start, key.iter().copied());
            response[2..4].copy_from_slice(&new_key_len.to_be_bytes());
            response[8..12].copy_from_slice(&new_body_len.to_be_bytes());
        }
    } else if recorded_key_len > 0 {
        response.drain(key_start..key_end);
        response[2..4].copy_from_slice(&0_u16.to_be_bytes());
        let new_body_len = u32::try_from(body_len - recorded_key_len)
            .expect("removing a Memcached key cannot overflow");
        response[8..12].copy_from_slice(&new_body_len.to_be_bytes());
    }
    Ok(())
}

fn rewrite_opaque(responses: &mut [Vec<u8>], requested_opaque: u32) {
    for response in responses {
        if response.len() >= 16 {
            response[12..16].copy_from_slice(&requested_opaque.to_be_bytes());
        }
    }
}

fn binary_get_miss(opcode: u8, opaque: u32) -> Vec<u8> {
    let mut response = vec![0_u8; 24];
    response[0] = 0x81;
    response[1] = opcode;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response[12..16].copy_from_slice(&opaque.to_be_bytes());
    response
}

fn response_status(response: &[u8]) -> Option<u16> {
    (response.len() >= 8).then(|| u16::from_be_bytes([response[6], response[7]]))
}

fn is_binary_get_opcode(opcode: u8) -> bool {
    matches!(opcode, GET | GETQ | GETK | GETKQ)
}

fn is_quiet_get_opcode(opcode: u8) -> bool {
    matches!(opcode, GETQ | GETKQ)
}

fn get_response_includes_key(opcode: u8) -> bool {
    matches!(opcode, GETK | GETKQ)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapts_getkq_hit_to_get_response() {
        let mut response = vec![0_u8; 24];
        response[0] = 0x81;
        response[1] = GETKQ;
        response[2..4].copy_from_slice(&3_u16.to_be_bytes());
        response[4] = 4;
        response[8..12].copy_from_slice(&12_u32.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes());
        response.extend_from_slice(b"keyvalue");
        let mut responses = vec![response];

        adapt_binary_get_responses(&mut responses, GET, 42, Some(b"key"), false).unwrap();

        assert_eq!(responses[0][1], GET);
        assert_eq!(&responses[0][2..4], &0_u16.to_be_bytes());
        assert_eq!(&responses[0][8..12], &9_u32.to_be_bytes());
        assert_eq!(&responses[0][12..16], &42_u32.to_be_bytes());
        assert_eq!(&responses[0][28..], b"value");
    }

    #[test]
    fn turns_quiet_get_miss_into_non_quiet_miss() {
        let mut responses = Vec::new();
        adapt_binary_get_responses(&mut responses, GET, 7, Some(b"key"), true).unwrap();

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0][1], GET);
        assert_eq!(&responses[0][6..8], &1_u16.to_be_bytes());
        assert_eq!(&responses[0][12..16], &7_u32.to_be_bytes());
    }
}
