/// SDK identity is advisory connection metadata, independent of application data.
pub fn is_client_library_info(command: &str, args: &[Vec<u8>]) -> bool {
    command.eq_ignore_ascii_case("CLIENT")
        && matches!(args, [subcommand, attribute, value]
            if subcommand.eq_ignore_ascii_case(b"SETINFO")
                && (attribute.eq_ignore_ascii_case(b"LIB-NAME")
                    || attribute.eq_ignore_ascii_case(b"LIB-VER"))
                && value.iter().all(u8::is_ascii_graphic))
}
