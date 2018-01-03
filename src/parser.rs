use nom;
use time;

use std::str::FromStr;

use nom::{digit, rest_s, space};

fn parse_month(s: &str) -> Result<i32, nom::simple_errors::Err> {
    match s {
        "Jan" => Ok(1),
        "Feb" => Ok(2),
        "Mar" => Ok(3),
        "Apr" => Ok(4),
        "May" => Ok(5),
        "Jun" => Ok(6),
        "Jul" => Ok(7),
        "Aug" => Ok(8),
        "Sep" => Ok(9),
        "Oct" => Ok(10),
        "Nov" => Ok(11),
        "Dec" => Ok(12),
        _ => Err(error_position!(
            nom::ErrorKind::OneOf,
            "Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec"
        )),
    }
}

named!(ts<&str,time::Tm>,
    do_parse! (
        month: map_res!(take!(3), parse_month) >>
        space >>
        day: map_res!(digit, FromStr::from_str) >>
        space >>
        hour: map_res!(digit, FromStr::from_str) >>
        tag_s!(":") >>
        minute: digit >>
        tag_s!(":") >>
        second: digit >>
        ({
          let mut tm = time::empty_tm();
          tm.tm_mon = month;
          tm.tm_mday = day;
          tm.tm_hour = hour;
          tm.tm_year = 2017 - 1900;
          tm
        })
    )
  );

#[derive(Debug)]
pub struct Syslog3164Message<'a> {
    pub pri: &'a str,
    pub ts: time::Tm,
    pub host: &'a str,
    pub tag: Option<(&'a str, Option<&'a str>)>,
    pub msg: &'a str,
}

fn tag_delim(ch: char) -> bool {
    ch == ' ' || ch == ':'
}

named!(parse_tag<&str, (&str,Option<&str>)>,
        alt!(
            do_parse!(
                tag: take_until_s!("[") >>
                tag_s!("[") >>
                pid: take_until_s!("]") >>
                tag_s!("]:") >>
                (
                    (tag,Some(pid))
                )
            ) |
            do_parse!(
                tag: take_till_s!(tag_delim) >>
                tag_s!(":") >>
                ({
                    (tag,None)
                })
            )
        )
);

#[test]
fn parse_cisco_variation_1() {
    use nom::IResult;
    let msg1 = r##"<189>Dec 26 23:33:18 10.4.104.208 3890188: Dec 26 2017 23:33:17.792 UTC: %ADJ-5-RESOLVE_REQ_FAIL: Adj resolve request failed for 192.168.57.182 on Vlan55"##;
    let res: IResult<&str, Syslog3164Message> = parse_syslog(msg1);
    assert!(res.is_done());

    let (_leftover, parsed) = res.unwrap();
    assert_eq!(
        parsed.msg,
        "%ADJ-5-RESOLVE_REQ_FAIL: Adj resolve request failed for 192.168.57.182 on Vlan55"
    );
    assert_eq!(parsed.tag, Some(("3890188", None)));
    assert_eq!(parsed.host, "10.4.104.208");
    assert_eq!(parsed.ts.to_utc().to_timespec().sec, 1517007600)
}

// Dec 26 2017 23:33:17.792
named!(better_ts<&str, time::Tm>,
        do_parse!(
            month: map_res!(take_s!(3), parse_month) >>
            tag_s!(" ") >>
            day: map_res!(take_s!(2), FromStr::from_str) >>
            tag_s!(" ") >>
            year: map_res!(take_s!(4), FromStr::from_str) >>
            tag_s!(" ") >>
            hour: map_res!(take_s!(2), FromStr::from_str) >>
            tag_s!(":") >>
            minute: map_res!(take_s!(2), FromStr::from_str) >>
            tag_s!(":") >>
            seconds: map_res!(take_s!(2), FromStr::from_str) >>
            tag_s!(".") >>
            millis: map_res!(take_s!(3), FromStr::from_str) >>
            tag_s!(" UTC: ") >>
            ({
                let mut tm = time::empty_tm();

                tm.tm_year = year;
                tm.tm_year = tm.tm_year - 1900;
                tm.tm_mon = month;
                tm.tm_mday = day;
                tm.tm_hour = hour;
                tm.tm_min = minute;
                tm.tm_sec = seconds;
                tm.tm_nsec = millis;
                tm.tm_nsec = tm.tm_nsec * 1000000;

                tm
            })
        )
);

named!(pub parse_syslog<&str, Syslog3164Message>,
    do_parse!(
      tag_s!("<") >>
      pri: digit >>
      tag_s!(">") >>
      ts: ts >>
      space >>
      host: take_until_s!(" ") >>
      space >>
      tag: opt!(parse_tag) >>
      space >>
      better_ts: opt!(better_ts) >>
      msg: rest_s >>
      (Syslog3164Message{pri: pri.into(),
         ts: ts,
         host: host.into(),
         tag: tag,
         msg: msg.into()
       })
    )
  );

#[test]
fn parse_nx_win_evt() {
    use nom::IResult;
    let msg1 = r##"<14>Dec 13 17:45:02 SANTA-CLAUS-W764.blerg.com nxWinEvt[123]: {"EventTime":"🐌017-12-19 17:45:02","Hostname":"fake-hostname","Keywords":-9214364837600034816,"EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4656,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":1,"Task":12804,"OpcodeValue":0,"RecordNumber":7613465324,"ProcessID":892,"ThreadID":908,"Channel":"Security","AccessReason":"-","AccessMask":"0x2","PrivilegeList":"-","RestrictedSidCount":"0","ProcessName":"C:\\Windows\\System32\\svchost.exe","EventReceivedTime":"2017-12-19 17:52:27","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog"}"##;
    let res: IResult<&str, Syslog3164Message> = parse_syslog(msg1);
    assert!(res.is_done());

    let (_leftover, parsed) = res.unwrap();
    assert_eq!(parsed.msg, &msg1[62..]);
    assert_eq!(parsed.ts.to_utc().to_timespec().sec, 1515862800)
}

#[test]
fn parse_nx_win_evt_pid_variation_1() {
    use nom::IResult;
    let msg1 = r##"<14>Dec 13 17:45:02 SANTA-CLAUS-W764.blerg.com nxWinEvt: {"EventTime":"2017-12-19 17:45:02","Hostname":"fake-hostname","Keywords":-9214364837600034816,"EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4656,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":1,"Task":12804,"OpcodeValue":0,"RecordNumber":7613465324,"ProcessID":892,"ThreadID":908,"Channel":"Security","AccessReason":"-","AccessMask":"0x2","PrivilegeList":"-","RestrictedSidCount":"0","ProcessName":"C:\\Windows\\System32\\svchost.exe","EventReceivedTime":"2017-12-19 17:52:27","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog"}"##;
    let res: IResult<&str, Syslog3164Message> = parse_syslog(msg1);
    assert!(res.is_done());

    let (_leftover, parsed) = res.unwrap();
    assert_eq!(parsed.msg, &msg1[57..]);
    assert_eq!(parsed.ts.to_utc().to_timespec().sec, 1515862800)
}
