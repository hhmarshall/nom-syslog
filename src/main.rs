#[macro_use]
extern crate nom;
use std::str::from_utf8;
use std::fmt::Debug;
use nom::{IResult, space, alpha, alphanumeric, digit, rest_s};
use std::str::FromStr;
use std::num::ParseIntError;


fn main() {


  named!(tstamp2<&str,&str > ,
    recognize! (
      tuple! (
        digit ,
        tag_s!(":") ,
        digit ,
        tag_s!(":") ,
        digit
      )
    )
  );

  #[derive(Debug)]
  struct B {
    // a: &str
    pri: String,
    b: String,
    c: String,
    tstamp: String,
    host: String,
    tag: String,
    msg: String
  }

  named!(hhm5<&str, B>,
    do_parse!(
      tag_s!("<") >>
      pri: digit >>
      tag_s!(">") >>
      thing1: take_until_s!(" ") >>
      space >>
      thing2: take_until_s!(" ") >>
      space >>
      // ts: tstamp2 >>
      ts: take_until_s!(" ") >>
      space >>
      host: take_until_s!(" ") >>
      space >>
      tag: take_until_s!(" ") >>
      space >>
      msg: rest_s >>
      (B{pri: pri.into(), 
         b:thing1.into(), 
         c:thing2.into(),
         tstamp:ts.into(),
         host:host.into(),
         tag:tag.into(),
         msg:msg.into()
       })
    )
  );
  let msg1 = r##"<14>Dec 19 17:45:02 SANTA-CLAUS-W764.blerg.com nxWinEvt[892]: {"EventTime":"2017-12-19 17:45:02","Hostname":"fake-hostname","Keywords":-9214364837600034816,"EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4656,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":1,"Task":12804,"OpcodeValue":0,"RecordNumber":7613465324,"ProcessID":892,"ThreadID":908,"Channel":"Security","AccessReason":"-","AccessMask":"0x2","PrivilegeList":"-","RestrictedSidCount":"0","ProcessName":"C:\\Windows\\System32\\svchost.exe","EventReceivedTime":"2017-12-19 17:52:27","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog"}"##;
  let res = hhm5(msg1);
  println!("hhm5 result {:?}", res);

}
