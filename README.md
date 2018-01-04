# nom-syslog

Crude parsing of rfc3164 syslog as nom exploration.

```
extern create nom_syslog;

// somewhere in your code
// ..
    parsed = nom_syslog::parse_syslog(data : &str)
    if !parsed.is_done() {
        // buffer too small? malformed data? our rules a little wrong?
    } else {
        // the message is ready!
        let (_leftover_buf, message) = parsed_res.unwrap();
        // do something cool!
    }
// ..
```
