use anyhow::{Result, bail};
use kafka_protocol::messages::{RequestKind, ResponseKind};
use kafka_protocol::records::{Compression, RecordBatchDecoder};

use super::{KafkaHeader, KafkaRecord};

pub(crate) fn records_from_produce(request: &RequestKind) -> Result<Vec<KafkaRecord>> {
    let RequestKind::Produce(request) = request else {
        bail!("request is not Produce");
    };
    if request.transactional_id.is_some() {
        bail!("transactional Kafka Produce is unsupported");
    }
    if request.acks != 1 {
        bail!("Kafka replay requires Produce acks=1, got {}", request.acks);
    }
    let mut result = Vec::new();
    for topic in &request.topic_data {
        for partition in &topic.partition_data {
            let Some(mut encoded) = partition.records.clone() else {
                continue;
            };
            for batch in RecordBatchDecoder::decode_all(&mut encoded)? {
                validate_batch(batch.version, batch.compression)?;
                for record in batch.records {
                    if record.transactional || record.control {
                        bail!("transactional or control Kafka records are unsupported");
                    }
                    result.push(convert_record(
                        topic.name.to_string(),
                        partition.index,
                        record,
                    ));
                }
            }
        }
    }
    Ok(result)
}

pub(crate) fn records_from_fetch(response: &ResponseKind) -> Result<Vec<KafkaRecord>> {
    let ResponseKind::Fetch(response) = response else {
        bail!("response is not Fetch");
    };
    if response.error_code != 0 {
        bail!("Kafka Fetch failed with error code {}", response.error_code);
    }
    let mut result = Vec::new();
    for topic in &response.responses {
        for partition in &topic.partitions {
            if partition.error_code != 0 {
                bail!(
                    "Kafka Fetch partition failed with error code {}",
                    partition.error_code
                );
            }
            let Some(mut encoded) = partition.records.clone() else {
                continue;
            };
            for batch in RecordBatchDecoder::decode_all(&mut encoded)? {
                validate_batch(batch.version, batch.compression)?;
                for record in batch.records {
                    if record.transactional || record.control {
                        continue;
                    }
                    result.push(convert_record(
                        topic.topic.to_string(),
                        partition.partition_index,
                        record,
                    ));
                }
            }
        }
    }
    Ok(result)
}

fn validate_batch(version: i8, compression: Compression) -> Result<()> {
    if version != 2 {
        bail!("Kafka replay only supports RecordBatch magic=2");
    }
    if compression != Compression::None {
        bail!("Kafka replay requires compression=none");
    }
    Ok(())
}

fn convert_record(
    topic: String,
    partition: i32,
    record: kafka_protocol::records::Record,
) -> KafkaRecord {
    KafkaRecord {
        topic,
        partition,
        timestamp_ms: record.timestamp,
        key: record.key,
        headers: record
            .headers
            .into_iter()
            .map(|(name, value)| KafkaHeader {
                name: name.to_string(),
                value,
            })
            .collect(),
        value: record.value,
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use kafka_protocol::messages::produce_request::{PartitionProduceData, TopicProduceData};
    use kafka_protocol::messages::{ProduceRequest, TopicName};
    use kafka_protocol::protocol::StrBytes;
    use kafka_protocol::records::{Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType};

    use super::*;

    #[test]
    fn extracts_uncompressed_produce_records() {
        let record = Record {
            transactional: false,
            control: false,
            partition_leader_epoch: 0,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            offset: 0,
            sequence: -1,
            timestamp: 123,
            key: Some(Bytes::from_static(b"key")),
            value: Some(Bytes::from_static(b"value")),
            headers: Default::default(),
        };
        let mut encoded = BytesMut::new();
        RecordBatchEncoder::encode(
            &mut encoded,
            [&record],
            &RecordEncodeOptions {
                version: 2,
                compression: Compression::None,
            },
        )
        .unwrap();
        let request = RequestKind::Produce(ProduceRequest::default().with_acks(1).with_topic_data(
            vec![TopicProduceData::default()
                    .with_name(TopicName(StrBytes::from_static_str("orders")))
                    .with_partition_data(vec![PartitionProduceData::default()
                        .with_index(0)
                        .with_records(Some(encoded.freeze()))])],
        ));

        let records = records_from_produce(&request).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].topic, "orders");
        assert_eq!(records[0].key.as_deref(), Some(b"key".as_slice()));
        assert_eq!(records[0].value.as_deref(), Some(b"value".as_slice()));
    }
}
