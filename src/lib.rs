#![feature(test)]

#[macro_use]
extern crate nom;
extern crate test;
extern crate time;

mod parser;
pub use self::parser::{parse_syslog, Syslog3164Message};