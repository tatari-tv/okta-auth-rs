use super::*;

// CarryBuffer is the line-assembly core shared by the real readers: split reads,
// CRLF, EOF flush, and the MAX_PASTE overflow guard all live here.

#[test]
fn single_complete_line() {
    let mut cb = CarryBuffer::new(1024);
    assert_eq!(
        cb.push(b"http://x/cb?code=a&state=b\n"),
        ReadOutcome::Line("http://x/cb?code=a&state=b".into())
    );
}

#[test]
fn split_read_buffers_until_newline() {
    let mut cb = CarryBuffer::new(1024);
    assert_eq!(cb.push(b"http://x/cb?"), ReadOutcome::Pending);
    assert_eq!(cb.push(b"code=a\n"), ReadOutcome::Line("http://x/cb?code=a".into()));
}

#[test]
fn split_multibyte_utf8_does_not_panic() {
    // A non-blocking chunk can split a multi-byte sequence; lossy decode handles it.
    let mut cb = CarryBuffer::new(1024);
    let bytes = "café\n".as_bytes(); // 'é' is two bytes
    let split = bytes.len() - 2; // cut inside 'é'
    assert_eq!(cb.push(&bytes[..split]), ReadOutcome::Pending);
    assert_eq!(cb.push(&bytes[split..]), ReadOutcome::Line("café".into()));
}

#[test]
fn second_line_in_chunk_is_retained_for_next_take() {
    let mut cb = CarryBuffer::new(1024);
    assert_eq!(cb.push(b"one\ntwo\n"), ReadOutcome::Line("one".into()));
    assert_eq!(cb.take_line(), Some("two".into()));
    assert_eq!(cb.take_line(), None);
}

#[test]
fn crlf_is_stripped() {
    let mut cb = CarryBuffer::new(1024);
    assert_eq!(cb.push(b"line\r\n"), ReadOutcome::Line("line".into()));
}

#[test]
fn eof_on_empty_buffer_reports_eof() {
    let mut cb = CarryBuffer::new(1024);
    assert_eq!(cb.push(&[]), ReadOutcome::Eof);
}

#[test]
fn eof_flushes_partial_line_then_reports_eof() {
    let mut cb = CarryBuffer::new(1024);
    assert_eq!(cb.push(b"partial-no-newline"), ReadOutcome::Pending);
    assert_eq!(cb.push(&[]), ReadOutcome::Line("partial-no-newline".into()));
    assert_eq!(cb.push(&[]), ReadOutcome::Eof);
}

#[test]
fn overflow_discards_overlong_line() {
    let mut cb = CarryBuffer::new(8);
    assert_eq!(cb.push(b"0123456789"), ReadOutcome::Overflow); // 10 bytes, no newline
}

#[test]
fn overflow_recovers_for_subsequent_line() {
    let mut cb = CarryBuffer::new(8);
    assert_eq!(cb.push(b"0123456789"), ReadOutcome::Overflow);
    assert_eq!(cb.push(b"ok\n"), ReadOutcome::Line("ok".into()));
}
