mod wire;

pub(crate) use wire::{
    BinaryFrame, BufferedReader, MemcachedRequest, MemcachedWireProtocol,
    binary_response_is_complete, read_binary_frame, read_text_request, read_text_response,
    text_request_line_is_valid,
};
