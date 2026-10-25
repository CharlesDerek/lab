//! UTF-16 command line encoding for executables using Microsoft CRT argv rules.
//! This is not shell escaping: the caller supplies an explicit .exe application.
use std::io;

pub(crate) fn command_line(program: &[u16], args: &[Vec<u16>]) -> io::Result<Vec<u16>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "Invalid Windows command line");
    if program.is_empty() || program.contains(&34) {
        return Err(invalid());
    }
    let mut out = Vec::new();
    for (index, arg) in std::iter::once(program)
        .chain(args.iter().map(Vec::as_slice))
        .enumerate()
    {
        if arg.contains(&0) || arg.len() > 32764 {
            return Err(invalid());
        }
        if index != 0 {
            out.push(32);
        }
        out.push(34);
        let mut slashes = 0;
        for &unit in arg {
            if unit == 92 {
                slashes += 1;
                continue;
            }
            out.extend(std::iter::repeat_n(
                92,
                slashes * if unit == 34 { 2 } else { 1 },
            ));
            slashes = 0;
            if unit == 34 {
                out.push(92);
            }
            out.push(unit);
        }
        out.extend(std::iter::repeat_n(92, slashes * 2));
        out.push(34);
        if out.len() >= 32767 {
            return Err(invalid());
        }
    }
    out.push(0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(arg: &str) -> String {
        let result = command_line(&[120], &[arg.encode_utf16().collect()]).unwrap();
        String::from_utf16(&result[..result.len() - 1]).unwrap()
    }
    #[test]
    fn crt_arguments_preserve_empty_whitespace_quotes_and_trailing_slashes() {
        assert_eq!(encode(""), r#""x" """#);
        assert_eq!(encode("a b\tc"), "\"x\" \"a b\tc\"");
        assert_eq!(encode(r#"a\b"c"#), r#""x" "a\b\"c""#);
        assert_eq!(encode(r#"a\"b"#), r#""x" "a\\\"b""#);
        assert_eq!(encode(r"C:\with space\"), r#""x" "C:\with space\\""#);
        assert_eq!(encode("&|<>^%!$()雪"), "\"x\" \"&|<>^%!$()雪\"");
    }
    #[test]
    fn command_line_enforces_windows_utf16_budget_and_rejects_nuls() {
        assert!(command_line(&[120], &[vec![97; 32760]]).is_ok());
        assert!(command_line(&[120], &[vec![97; 32761]]).is_err());
        assert!(command_line(&[120], &[vec![0]]).is_err());
        assert!(command_line(&[34], &[]).is_err());
        // Preserve Windows OS strings, including unpaired surrogate code units.
        assert_eq!(
            command_line(&[120], &[vec![0xd800]]).unwrap(),
            [34, 120, 34, 32, 34, 0xd800, 34, 0]
        );
    }
}
