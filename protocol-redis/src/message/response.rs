//! RESP response shape and scalar locations projected to shared value execution.
use super::*;
use redis_protocol::resp2::types::BytesFrame as Frame;

pub struct ResponseMessage {
    frame: Frame,
    original: Bytes,
}

impl ResponseMessage {
    pub fn decode(bytes: Bytes) -> Result<Self> {
        let (frame, length) = redis_protocol::resp2::decode::decode_bytes(&bytes)?
            .context("recorded Redis response is incomplete")?;
        ensure!(
            length == bytes.len(),
            "recorded Redis response has trailing bytes"
        );
        Ok(Self {
            frame,
            original: bytes,
        })
    }
}

impl ProtocolMessage for ResponseMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let mut values = BTreeMap::new();
        let structure = project(&self.frame, "", &mut values);
        Ok(ProjectedMessage { structure, values })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        ensure!(
            selector == &json!({"kind":"value"}),
            "unsupported Redis response selector"
        );
        Ok(self.project()?.values.into_keys().collect())
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        let projection = self.project()?;
        let locations = self.locate(selector)?;
        Ok(json!({"values":locations.into_iter().map(|location| {
            let capture = traffic_model::capture::capture_body(&projection.values[&location].bytes, usize::MAX);
            json!({"location":location,"capture":capture})
        }).collect::<Vec<_>>()}))
    }
}

impl MessageEncoder for ResponseMessage {
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        let source = self.project()?;
        ensure!(
            source.values.keys().eq(values.keys()),
            "Redis response value inventory changed"
        );
        if source
            .values
            .iter()
            .all(|(path, value)| value.bytes == values[path])
        {
            return Ok(self.original.clone());
        }
        let mut output = Vec::new();
        encode(&self.frame, "", values, &mut output)?;
        Ok(output.into())
    }
}

fn project(frame: &Frame, path: &str, values: &mut BTreeMap<String, ProjectedValue>) -> Value {
    match frame {
        Frame::BulkString(bytes) => {
            values.insert(path.into(), ProjectedValue::bytes(bytes.clone()));
            json!({"kind":"bulk"})
        }
        Frame::SimpleString(bytes) => {
            values.insert(path.into(), ProjectedValue::bytes(bytes.clone()));
            json!({"kind":"simple"})
        }
        Frame::Integer(value) => {
            values.insert(path.into(), ProjectedValue::json(value.to_string()));
            json!({"kind":"integer"})
        }
        Frame::Array(items) => {
            json!({"kind":"array","items":items.iter().enumerate().map(|(index,item)| project(item,&format!("{path}/{index}"),values)).collect::<Vec<_>>()})
        }
        Frame::Null => json!({"kind":"null"}),
        Frame::Error(error) => json!({"kind":"error","error":error.to_string()}),
    }
}

fn encode(
    frame: &Frame,
    path: &str,
    values: &BTreeMap<String, Bytes>,
    output: &mut Vec<u8>,
) -> Result<()> {
    match frame {
        Frame::BulkString(_) => {
            let value = &values[path];
            output.extend_from_slice(format!("${}\r\n", value.len()).as_bytes());
            output.extend_from_slice(value);
            output.extend_from_slice(b"\r\n");
        }
        Frame::SimpleString(_) => {
            let value = &values[path];
            ensure!(
                !value.contains(&b'\r') && !value.contains(&b'\n'),
                "Redis simple string contains a line break"
            );
            output.push(b'+');
            output.extend_from_slice(value);
            output.extend_from_slice(b"\r\n");
        }
        Frame::Integer(_) => {
            let value = std::str::from_utf8(&values[path])?.parse::<i64>()?;
            output.extend_from_slice(format!(":{value}\r\n").as_bytes());
        }
        Frame::Array(items) => {
            output.extend_from_slice(format!("*{}\r\n", items.len()).as_bytes());
            for (index, item) in items.iter().enumerate() {
                encode(item, &format!("{path}/{index}"), values, output)?;
            }
        }
        Frame::Null => output.extend_from_slice(b"$-1\r\n"),
        Frame::Error(error) => {
            output.push(b'-');
            output.extend_from_slice(error.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
    }
    Ok(())
}
