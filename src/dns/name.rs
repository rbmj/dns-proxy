use std::fmt;
use std::str::FromStr;
use std::io::{Cursor, Write};
use std::iter::Rev;
use std::slice::Iter;
use byteorder::WriteBytesExt;
use itertools::Itertools;
use dns_parser::Error::LabelIsNotAscii;

use super::Error;

#[derive(Clone)]
pub struct Label {
    data: String
}

impl Label {
    fn check(s: &str) -> Result<(), Error> {
        if !s.chars().all(|c| c.is_digit(36) || c == '-') || s.len() == 0 {
            return Err(Error::ParserError(LabelIsNotAscii));
        }
        Ok(())
    }
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_string(s.to_string())
    }
    pub fn from_string(s: String) -> Result<Self, Error> {
        try!(Self::check(s.as_str()));
        Ok(Label { data: s })
    }
    pub fn as_str(&self) -> &str {
        self.data.as_str()
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        cursor.write_u8(self.data.len() as u8)?;
        if let Err(e) = cursor.write_all(self.as_str().as_bytes()) {
            return Err(Error::IOError(e));
        }
        Ok(())
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.data.fmt(f)
    }
}

#[derive(Clone)]
pub struct Name {
    labels: Vec<Label>
}

impl Name {
    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_str(s.as_str())
    }
    pub fn to_string(&self) -> String {
        self.iter().join(".")
    }
    pub fn push(&mut self, l: Label) {
        self.labels.push(l);
    }
    pub fn pop(&mut self) {
        self.labels.pop();
    }
    pub fn iter(&self) -> Rev<Iter<Label>> {
        self.labels.iter().rev()
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        for l in self.iter() {
            try!(l.serialize(cursor));
        }
        try!(cursor.write_u8(0));
        Ok(())
    }
}

impl FromStr for Name {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(Name { labels: s.split('.').rev().map(|s| Label::from_str(s))
            .collect::<Result<Vec<_>, Error>>()? })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

