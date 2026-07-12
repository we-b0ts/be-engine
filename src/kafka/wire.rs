use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use kafka_protocol::messages::{ApiKey, RequestHeader, RequestKind, ResponseHeader, ResponseKind};
use kafka_protocol::protocol::{Decodable, Encodable, decode_request_header_from_buffer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub(crate) struct DecodedKafkaRequest {
    pub(crate) header: RequestHeader,
    pub(crate) api_key: ApiKey,
    pub(crate) request: RequestKind,
}

#[derive(Debug)]
pub(crate) struct DecodedKafkaResponse {
    pub(crate) response: ResponseKind,
}

pub(crate) async fn read_frame<R>(reader: &mut R, max_frame_bytes: usize) -> Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let first = match reader.read_u8().await {
        Ok(byte) => byte,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("failed to read Kafka frame size"),
    };
    let mut size_bytes = [first, 0, 0, 0];
    reader
        .read_exact(&mut size_bytes[1..])
        .await
        .context("Kafka connection closed inside frame size")?;
    let size = i32::from_be_bytes(size_bytes);
    if size < 0 {
        bail!("Kafka frame has negative size {size}");
    }
    let size = size as usize;
    if size > max_frame_bytes {
        bail!("Kafka frame size {size} exceeds configured limit {max_frame_bytes}");
    }
    let mut payload = vec![0_u8; size];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed to read Kafka frame payload")?;
    Ok(Some(Bytes::from(payload)))
}

pub(crate) async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let size = i32::try_from(payload.len()).context("Kafka frame is larger than i32::MAX")?;
    writer.write_i32(size).await?;
    writer.write_all(payload).await?;
    Ok(())
}

pub(crate) fn decode_request(payload: &Bytes) -> Result<DecodedKafkaRequest> {
    let mut body = payload.clone();
    let header = decode_request_header_from_buffer(&mut body)
        .context("failed to decode Kafka request header")?;
    let api_key = ApiKey::try_from(header.request_api_key)
        .map_err(|_| anyhow!("unknown Kafka API key {}", header.request_api_key))?;
    let request = RequestKind::decode(api_key, &mut body, header.request_api_version)
        .with_context(|| {
            format!(
                "failed to decode Kafka {:?} request version {}",
                api_key, header.request_api_version
            )
        })?;
    Ok(DecodedKafkaRequest {
        header,
        api_key,
        request,
    })
}

pub(crate) fn decode_response(
    payload: &Bytes,
    api_key: ApiKey,
    api_version: i16,
) -> Result<DecodedKafkaResponse> {
    let mut body = payload.clone();
    ResponseHeader::decode(&mut body, api_key.response_header_version(api_version))
        .context("failed to decode Kafka response header")?;
    let response = ResponseKind::decode(api_key, &mut body, api_version).with_context(|| {
        format!("failed to decode Kafka {api_key:?} response version {api_version}")
    })?;
    Ok(DecodedKafkaResponse { response })
}

pub(crate) fn response_correlation_id(payload: &Bytes) -> Result<i32> {
    let bytes = payload
        .get(..4)
        .context("Kafka response is shorter than its correlation id")?;
    Ok(i32::from_be_bytes(
        bytes.try_into().expect("four byte slice"),
    ))
}

pub(crate) fn encode_response(
    correlation_id: i32,
    api_key: ApiKey,
    api_version: i16,
    response: &ResponseKind,
) -> Result<Bytes> {
    let mut payload = BytesMut::new();
    ResponseHeader::default()
        .with_correlation_id(correlation_id)
        .encode(&mut payload, api_key.response_header_version(api_version))?;
    response.encode(&mut payload, api_version)?;
    Ok(payload.freeze())
}
