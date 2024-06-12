#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::{
    cell::{BorrowError, RefCell},
    fmt::{self, Debug, Display},
    io::{Seek, SeekFrom},
    rc::Rc,
    sync::OnceLock,
};

use binrw::{binrw, BinRead, BinResult, BinWrite};
use uuid::Uuid;

pub mod file;
pub use file::*;
pub mod fv;
pub use fv::*;
pub mod section;
pub use section::*;
/*pub mod fit;
pub use fit::*;
pub mod bpm_km;
pub use bpm_km::*;
pub mod mcu;
pub use mcu::*;
pub mod acm;
pub use acm::*;*/

pub trait InnerError: Display + Debug + Send + Sync {}
impl<T: Display + Debug + Send + Sync> InnerError for T {}

#[derive(thiserror::Error, Debug)]
pub enum FfsLibError {
    #[error("BinRw: {0}")]
    BinRw(#[from] binrw::Error),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unexpected enum value for {name}: {got}")]
    UnexpectedEnumValue {
        name: String,
        got: Box<dyn InnerError>,
    },
    #[error("Not enough input: expected {expected}: {got}")]
    NotEnoughInput { expected: usize, got: usize },
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Reach the end of FV content")]
    EndOfFv,
    #[error("BorrowError: {0}")]
    BorrowError(#[from] BorrowError),
    #[error("Item not found")]
    NotFound,
}

impl FfsLibError {
    fn into_binrw_err(self, pos: u64) -> binrw::Error {
        binrw::Error::Custom {
            pos,
            err: Box::new(self),
        }
    }
}

struct Checksum16<T> {
    inner: T,
    check: core::num::Wrapping<u16>,
    tmp: Option<u8>,
}

impl<T> Checksum16<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            check: core::num::Wrapping(0),
            tmp: None,
        }
    }

    fn check(&self) -> u16 {
        self.check.0
    }
}

impl<T: binrw::io::Read> binrw::io::Read for Checksum16<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.inner.read(buf)?;

        let mut idx = 0;
        if let Some(tmp) = self.tmp {
            idx = 1;
            self.check += u16::from_le_bytes([tmp, buf[0]]);
            self.tmp = None;
        }
        while idx + 1 < size {
            self.check += u16::from_le_bytes([buf[idx], buf[idx + 1]]);
            idx += 2;
        }
        if idx < size {
            self.tmp = Some(buf[size - 1]);
        }
        Ok(size)
    }
}

impl<T: Seek> Seek for Checksum16<T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Cloned from https://github.com/jam1garner/binrw/blob/master/binrw/tests/derive/struct.rs
struct Checksum8<T> {
    inner: T,
    check: core::num::Wrapping<u8>,
}

impl<T> Checksum8<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            check: core::num::Wrapping(0),
        }
    }

    fn check(&self) -> u8 {
        self.check.0
    }
}

impl<T: binrw::io::Read> binrw::io::Read for Checksum8<T> {
    fn read(&mut self, buf: &mut [u8]) -> binrw::io::Result<usize> {
        let size = self.inner.read(buf)?;
        for b in &buf[0..size] {
            self.check += b;
        }
        Ok(size)
    }
}

impl<T: Seek> Seek for Checksum8<T> {
    fn seek(&mut self, pos: SeekFrom) -> binrw::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[binrw::parser(reader, endian)]
fn read_remaining_length<'a, A: Clone, T: BinRead<Args<'a> = A>>(
    remaining_length: usize,
    args: A,
) -> BinResult<Vec<T>> {
    let remaining_length = remaining_length as u64;
    let start_pos = reader.stream_position()?;
    let mut result = vec![];
    while reader.stream_position()? - start_pos < remaining_length {
        result.push(T::read_options(reader, endian, args.clone())?);
    }

    Ok(result)
}

#[binrw::parser(reader, endian)]
fn read_remaining_length_rc_refcell<'a, A: Clone, T: BinRead<Args<'a> = A>>(
    remaining_length: usize,
    args: A,
) -> BinResult<Vec<Rc<RefCell<T>>>> {
    let remaining_length = remaining_length as u64;
    let start_pos = reader.stream_position()?;
    let mut result = vec![];
    while reader.stream_position()? - start_pos < remaining_length {
        result.push(Rc::new(RefCell::new(T::read_options(
            reader,
            endian,
            args.clone(),
        )?)));
    }

    Ok(result)
}

#[binrw::parser(reader, endian)]
fn until_terminator<'a, A: Clone, T: BinRead<Args<'a> = A> + PartialEq>(
    terminator: T,
    includes_terminator: bool,
    max_length: Option<usize>,
    args: A,
) -> BinResult<Vec<T>> {
    let max_length = max_length.map(|v| v as u64);
    let start_pos = reader.stream_position()?;
    let mut result = vec![];
    loop {
        let new_obj = T::read_options(reader, endian, args.clone())?;
        if new_obj == terminator {
            if includes_terminator {
                result.push(new_obj);
            }
            break;
        } else {
            result.push(new_obj);
        }
        if let Some(max_len) = max_length {
            if reader.stream_position()? - start_pos >= max_len {
                break;
            }
        }
    }

    Ok(result)
}

#[binrw::parser(reader, endian)]
fn read_rc_refcell<'a, A: Clone, T: BinRead<Args<'a> = A>>(args: A) -> BinResult<Rc<RefCell<T>>> {
    Ok(Rc::new(RefCell::new(T::read_options(
        reader,
        endian,
        args.clone(),
    )?)))
}

#[binrw::writer(writer, endian)]
fn write_vec_rc_refcell<'a, A: Clone, T: BinWrite<Args<'a> = A>>(
    obj: &Vec<Rc<RefCell<T>>>,
    args: A,
) -> BinResult<()> {
    for entry in obj.iter() {
        entry.borrow().write_options(writer, endian, args.clone())?;
    }
    Ok(())
}

#[binrw::writer(writer, endian)]
fn write_rc_refcell<'a, A: Clone, T: BinWrite<Args<'a> = A>>(
    obj: &Rc<RefCell<T>>,
    args: A,
) -> BinResult<()> {
    obj.borrow().write_options(writer, endian, args.clone())?;
    Ok(())
}

/// A wrapper struct for Uuid to implement binrw for it
#[binrw]
#[br(little)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UuidBytes {
    #[br(map = |raw: [u8;16]| Uuid::from_bytes_le(raw))]
    #[bw(map = |val: &Uuid| val.to_bytes_le())]
    uuid: Uuid,
}

impl AsRef<Uuid> for UuidBytes {
    fn as_ref(&self) -> &Uuid {
        &self.uuid
    }
}

impl Debug for UuidBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.uuid)
    }
}

impl std::fmt::Display for UuidBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uuid)
    }
}

impl From<Uuid> for UuidBytes {
    fn from(value: Uuid) -> Self {
        Self { uuid: value }
    }
}

fn buf_fmt(val: &Vec<u8>, f: &mut fmt::Formatter) -> fmt::Result {
    for i in 0..val.len() {
        if i % 16 == 0 {
            write!(f, "\n  {:02X}", val[i])?;
        } else {
            write!(f, " {:02X}", val[i])?;
        }
    }
    write!(f, "")
}

#[derive(Debug, Clone)]
pub enum FfsComponent {
    Fv(Rc<RefCell<Fv>>),
    File(Rc<RefCell<File>>),
    Section(Rc<RefCell<Section>>),
}

impl From<Fv> for FfsComponent {
    fn from(value: Fv) -> Self {
        Self::Fv(Rc::new(RefCell::new(value)))
    }
}

impl From<&Rc<RefCell<Fv>>> for FfsComponent {
    fn from(value: &Rc<RefCell<Fv>>) -> Self {
        Self::Fv(value.clone())
    }
}

impl From<File> for FfsComponent {
    fn from(value: File) -> Self {
        Self::File(Rc::new(RefCell::new(value)))
    }
}

impl From<&Rc<RefCell<File>>> for FfsComponent {
    fn from(value: &Rc<RefCell<File>>) -> Self {
        Self::File(value.clone())
    }
}

impl From<Section> for FfsComponent {
    fn from(value: Section) -> Self {
        Self::Section(Rc::new(RefCell::new(value)))
    }
}

impl From<&Rc<RefCell<Section>>> for FfsComponent {
    fn from(value: &Rc<RefCell<Section>>) -> Self {
        Self::Section(value.clone())
    }
}

impl FfsComponent {
    pub fn as_fv(&self) -> Option<Rc<RefCell<Fv>>> {
        if let Self::Fv(obj) = self {
            Some(obj.clone())
        } else {
            None
        }
    }

    pub fn as_ffs(&self) -> Option<Rc<RefCell<File>>> {
        if let Self::File(obj) = self {
            Some(obj.clone())
        } else {
            None
        }
    }

    pub fn as_section(&self) -> Option<Rc<RefCell<Section>>> {
        if let Self::Section(obj) = self {
            Some(obj.clone())
        } else {
            None
        }
    }

    pub fn get_child(&self, idx: usize) -> Result<Self, FfsLibError> {
        match self {
            Self::Fv(obj) => obj
                .try_borrow()?
                .files()
                .get(idx)
                .map(FfsComponent::from)
                .ok_or(FfsLibError::NotFound),
            Self::File(obj) => {
                if let FilePayload::Sections(sections) = obj.try_borrow()?.payload() {
                    sections
                        .get(idx)
                        .map(FfsComponent::from)
                        .ok_or(FfsLibError::NotFound)
                } else {
                    Err(FfsLibError::NotFound)
                }
            }
            Self::Section(obj) => match obj.try_borrow()?.payload() {
                SectionPayload::COMPRESSION {
                    uncompressed_length: _,
                    compression_type: _,
                    data,
                } => data
                    .get(idx)
                    .map(FfsComponent::from)
                    .ok_or(FfsLibError::NotFound),
                SectionPayload::DISPOSABLE { image } => image
                    .get(idx)
                    .map(FfsComponent::from)
                    .ok_or(FfsLibError::NotFound),
                SectionPayload::FIRMWARE_VOLUME_IMAGE { fv } => {
                    if idx == 0 {
                        Ok(fv.into())
                    } else {
                        Err(FfsLibError::NotFound)
                    }
                }
                SectionPayload::GUID_DEFINED {
                    definition: _,
                    data_offset: _,
                    attributes: _,
                    data,
                } => {
                    if let GuidDefinedData::Processed(data) = data {
                        data.get(idx)
                            .map(FfsComponent::from)
                            .ok_or(FfsLibError::NotFound)
                    } else {
                        Err(FfsLibError::NotFound)
                    }
                }
                _ => Err(FfsLibError::NotFound),
            },
        }
    }

    pub fn children(&self) -> FfsCompIter {
        FfsCompIter {
            idx: 0,
            inner: self.clone(),
        }
    }

    pub fn search(
        &self,
        callback: &mut dyn FnMut(&FfsComponent) -> Result<SearchAction, Box<dyn std::error::Error>>,
        options: &SearchOption,
    ) -> Result<SearchAction, Box<dyn std::error::Error>> {
        let mut action = SearchAction::Continue;
        if options.test(self)? {
            action = callback(self)?;
        }
        if action == SearchAction::Abort {
            return Ok(action);
        }

        if action == SearchAction::Continue {
            let mut child_options = options.clone();
            if let Some(lvl) = child_options.level {
                if lvl == 0 {
                    return Ok(action);
                }
                child_options.level = Some(lvl - 1);
            }
            for child in self.children() {
                let child = child?;
                let action = child.search(callback, &child_options)?;
                if action == SearchAction::Abort {
                    return Ok(action);
                }
            }
        }
        Ok(action)
    }
}

pub struct FfsCompIter {
    idx: usize,
    inner: FfsComponent,
}

impl Iterator for FfsCompIter {
    type Item = Result<FfsComponent, FfsLibError>;
    fn next(&mut self) -> Option<Self::Item> {
        let nxt = self.inner.get_child(self.idx);
        if let Err(FfsLibError::NotFound) = nxt {
            return None;
        }
        self.idx += 1;
        Some(nxt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchAction {
    Continue,
    Abort,
    SkipChildren,
}

#[derive(Debug, Clone, Default)]
pub struct SearchOption {
    target: Option<Uuid>,
    level: Option<usize>,
}

impl SearchOption {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn target(mut self, target: Option<Uuid>) -> Self {
        self.target = target;
        self
    }

    pub fn level(mut self, level: Option<usize>) -> Self {
        self.level = level;
        self
    }

    fn test(&self, obj: &FfsComponent) -> Result<bool, FfsLibError> {
        if let Some(uuid) = &self.target {
            match obj {
                FfsComponent::Fv(fv) => {
                    if !fv
                        .try_borrow()?
                        .ext_hdr()
                        .as_ref()
                        .is_some_and(|ext| ext.fv_name().as_ref().eq(uuid))
                    {
                        return Ok(false);
                    }
                }
                FfsComponent::File(ffs) => {
                    if !ffs.try_borrow()?.hdr().name().as_ref().eq(uuid) {
                        return Ok(false);
                    }
                }
                _ => {
                    return Ok(false);
                }
            }
        }

        if let Some(level) = &self.level {
            if *level == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

static FINDER: OnceLock<memchr::memmem::Finder> = OnceLock::new();
pub struct FindFvIter<'data> {
    data: &'data [u8],
}

impl<'data> FindFvIter<'data> {
    pub fn new(data: &'data [u8]) -> Self {
        Self { data }
    }
}

impl<'data> Iterator for FindFvIter<'data> {
    type Item = Fv;
    fn next(&mut self) -> Option<Self::Item> {
        while !self.data.is_empty() {
            let fv_match = FINDER
                .get_or_init(|| memchr::memmem::Finder::new(&FvHdr::ZERO_VECTOR))
                .find(self.data);
            if let Some(fv_match) = fv_match {
                let mut reader = std::io::Cursor::new(&self.data[fv_match..]);
                match Fv::read(&mut reader) {
                    Ok(fv) => {
                        self.data = &self.data[fv.hdr().fv_length() as usize..];
                        return Some(fv);
                    }
                    Err(_) => self.data = &self.data[fv_match + FvHdr::ZERO_VECTOR.len()..],
                }
            } else {
                break;
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_search() -> anyhow::Result<()> {
        let fv_sections = std::fs::read("test/9E21FD93-9C72-4c15-8C4B-E77F1DB2D792SEC1.guided")?;
        let mut reader = Cursor::new(&fv_sections);
        let section: FfsComponent = Section::read(&mut reader)?.into();
        let ref_data = std::fs::read("test/D6A2CB7F-6A18-4e2f-B43B-9920A733700A.ffs")?;
        let mut len = 0;
        section
            .search(
                &mut |comp| {
                    let mut buf = vec![];
                    let mut writer = Cursor::new(&mut buf);
                    comp.as_ffs().unwrap().borrow().write(&mut writer).unwrap();
                    len = buf.len();
                    assert_eq!(ref_data.len(), buf.len());
                    for i in 0..buf.len() {
                        // skip state field because it can be different depends on FV's erase polarity
                        if i != 0x17 {
                            assert_eq!(buf[i], ref_data[i]);
                        }
                    }
                    Ok(SearchAction::Abort)
                },
                &SearchOption::default()
                    .target(Some(uuid::uuid!("D6A2CB7F-6A18-4e2f-B43B-9920A733700A"))),
            )
            .unwrap();
        Ok(())
    }
}
