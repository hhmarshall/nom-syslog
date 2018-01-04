#![feature(test)]
extern crate nom;
extern crate nom_syslog;
extern crate test;

use nom_syslog::{Syslog3164Message,parse_syslog};

#[bench]
fn bench_parser(b: &mut test::Bencher) {
    use nom::IResult;
    let msg1 = r##"<14>Dec 13 17:45:02 SANTA-CLAUS-W764.blerg.com nxWinEvt[892]: {"EventTime":"2017-12-19 17:45:02","Hostname":"fake-hostname","Keywords":-9214364837600034816,"EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4656,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Version":1,"Task":12804,"OpcodeValue":0,"RecordNumber":7613465324,"ProcessID":892,"ThreadID":908,"Channel":"Security","AccessReason":"-","AccessMask":"0x2","PrivilegeList":"-","RestrictedSidCount":"0","ProcessName":"C:\\Windows\\System32\\svchost.exe","EventReceivedTime":"2017-12-19 17:52:27","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog"}"##;
    b.iter(|| {
        let res: IResult<&str, Syslog3164Message> = parse_syslog(msg1);
        assert!(res.is_done());
    });
}
