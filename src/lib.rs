#[macro_use]
extern crate nom;
extern crate time;

pub use nom::{IResult};

mod parser;
pub use self::parser::{parse_syslog, Syslog3164Message};