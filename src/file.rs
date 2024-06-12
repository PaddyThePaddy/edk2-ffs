use std::{
    cell::RefCell,
    fmt::Debug,
    io::{Cursor, Seek, SeekFrom},
    num::Wrapping,
    rc::Rc,
};

use binrw::{
    binrw,
    meta::{EndianKind, ReadEndian, WriteEndian},
    BinRead, BinResult, BinWrite, Endian,
};
use getset::{CopyGetters, Getters, MutGetters};

use crate::{
    read_remaining_length_rc_refcell, write_vec_rc_refcell, Checksum8, FfsLibError, Section,
    UuidBytes,
};

#[derive(Debug, Clone, Getters, MutGetters)]
pub struct File {
    #[getset(get = "pub", get_mut = "pub")]
    hdr: FileHdr,
    #[getset(get = "pub", get_mut = "pub")]
    payload: FilePayload,
}

impl ReadEndian for File {
    const ENDIAN: EndianKind = EndianKind::Endian(Endian::Little);
}

impl WriteEndian for File {
    const ENDIAN: EndianKind = EndianKind::Endian(Endian::Little);
}

impl BinRead for File {
    type Args<'a> = (u64,);

    fn read_options<R: std::io::prelude::Read + std::io::prelude::Seek>(
        reader: &mut R,
        endian: Endian,
        args: (u64,),
    ) -> BinResult<Self> {
        let start_pos = reader.stream_position()?;
        if (start_pos - args.0) % 8 != 0 {
            reader.seek(SeekFrom::Current(8 - ((start_pos - args.0) % 8) as i64))?;
        }
        let hdr = FileHdr::read_options(reader, endian, ())?;
        let payload = FilePayload::read_options(
            reader,
            endian,
            (
                hdr.file_type().is_sectioned(),
                hdr.size()
                    - if hdr.attributes().large_file() {
                        32
                    } else {
                        24
                    },
            ),
        )?;
        Ok(Self { hdr, payload })
    }
}

impl BinWrite for File {
    type Args<'a> = (u8,);
    fn write_options<W: std::io::prelude::Write + std::io::prelude::Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: (u8,),
    ) -> BinResult<()> {
        let start_pos = writer.stream_position()?;
        if start_pos % 8 != 0 {
            for _ in 0..8 - (start_pos % 8) {
                if args.0 != 0 {
                    [0xffu8].write_options(writer, endian, ())?;
                } else {
                    [0u8].write_options(writer, endian, ())?;
                }
            }
        }
        let mut hdr_buf = Vec::with_capacity(FileHdr::MIN_HDR_LENGTH);
        let mut hdr_buf_cursor = Cursor::new(&mut hdr_buf);
        let mut payload_buf = Vec::with_capacity(self.hdr().size() - FileHdr::MIN_HDR_LENGTH);
        let mut payload_buf_cursor = Cursor::new(&mut payload_buf);

        self.hdr.write_options(&mut hdr_buf_cursor, endian, ())?;
        self.payload
            .write_options(&mut payload_buf_cursor, endian, (0,))?;
        let mut total_len = hdr_buf_cursor.position() + payload_buf_cursor.position();
        let requires_extended_size = self.hdr.attributes().large_file() || total_len >= (1 << 24);
        if requires_extended_size {
            if !self.hdr.attributes().large_file() {
                hdr_buf_cursor.seek(SeekFrom::Start(20))?;
                (self.hdr.attributes.data | FileAttribute::FFS_ATTRIB_LARGE_FILE).write_options(
                    &mut hdr_buf_cursor,
                    endian,
                    (),
                )?;
                total_len += 4;
            }
            hdr_buf_cursor.seek(SeekFrom::Start(24))?;
            (total_len as u32).write_options(&mut hdr_buf_cursor, endian, ())?;
        } else {
            let len_bytes = total_len.to_le_bytes();
            hdr_buf_cursor.seek(SeekFrom::Start(20))?;
            len_bytes[..3].write_options(&mut hdr_buf_cursor, endian, ())?;
        }

        let mut hdr_checksum = Wrapping(0u8);
        hdr_buf.iter().for_each(|b| hdr_checksum -= *b);
        hdr_checksum += hdr_buf[FileHdr::HDR_CHECKSUM_OFFSET];
        hdr_checksum += hdr_buf[FileHdr::DATA_CHECKSUM_OFFSET];
        hdr_checksum += hdr_buf[FileHdr::STATE_CHECKSUM_OFFSET];
        hdr_buf[FileHdr::HDR_CHECKSUM_OFFSET] = hdr_checksum.0;

        let mut data_checksum = Wrapping(0xAAu8);
        if self.hdr().attributes().file_checksum() {
            payload_buf.iter().for_each(|b| data_checksum -= *b);
        }
        hdr_buf[17] = data_checksum.0;

        hdr_buf.write_options(writer, endian, ())?;
        payload_buf.write_options(writer, endian, ())?;
        Ok(())
    }
}

#[binrw]
#[br(import(has_section: bool, length: usize))]
#[bw(import(start_pos: u64))]
#[derive(custom_debug::Debug, Clone)]
pub enum FilePayload {
    #[br(pre_assert(has_section))]
    Sections(
        #[br(parse_with(read_remaining_length_rc_refcell), args(length, ()))]
        #[bw(write_with(write_vec_rc_refcell), args((start_pos,)))]
        Vec<Rc<RefCell<Section>>>,
    ),
    #[br(pre_assert(!has_section))]
    Raw(
        #[br(count(length))]
        #[debug(skip)]
        Vec<u8>,
    ),
}

impl FilePayload {
    pub fn sections(&self) -> Option<&[Rc<RefCell<Section>>]> {
        match self {
            FilePayload::Sections(sect) => Some(sect.as_slice()),
            _ => None,
        }
    }
}

/// Each file begins with the header that describe the
/// contents and state of the files.
#[binrw]
#[brw(little)]
#[br(stream = stream,
     map_stream = Checksum8::new,
    assert(stream.check() == file_checksum.wrapping_add(state.data)))]
#[derive(custom_debug::Debug, Clone, Getters, CopyGetters)]
pub struct FileHdr {
    /// This GUID is the file name. It is used to uniquely identify the file.
    #[getset(get = "pub")]
    name: UuidBytes,

    /// The IntegrityCheck.Checksum.Header field is an 8-bit checksum of the file
    /// header. The State and IntegrityCheck.Checksum.File fields are assumed
    /// to be zero and the checksum is calculated such that the entire header sums to zero.
    #[debug(format = "{0:} | {0:#X}")]
    hdr_checksum: u8,

    /// If the FFS_ATTRIB_CHECKSUM (see definition below) bit of the Attributes
    /// field is set to one, the IntegrityCheck.Checksum.File field is an 8-bit
    /// checksum of the file data.
    /// If the FFS_ATTRIB_CHECKSUM bit of the Attributes field is cleared to zero,
    /// the IntegrityCheck.Checksum.File field must be initialized with a value of
    /// 0xAA. The IntegrityCheck.Checksum.File field is valid any time the
    /// EFI_FILE_DATA_VALID bit is set in the State field.
    #[getset(get_copy = "pub")]
    #[debug(format = "{0:} | {0:#X}")]
    file_checksum: u8,

    /// Identifies the type of file.
    #[getset(get = "pub")]
    file_type: FileType,

    /// Declares various file attribute bits.
    #[getset(get = "pub")]
    attributes: FileAttribute,

    /// The length of the file in bytes, including the FFS header.
    /// The length of the file data is either (Size - sizeof(EFI_FFS_FILE_HEADER)). This calculation means a
    /// zero-length file has a Size of 24 bytes, which is sizeof(EFI_FFS_FILE_HEADER).
    /// Size is not required to be a multiple of 8 bytes. Given a file F, the next file header is
    /// located at the next 8-byte aligned firmware volume offset following the last byte of the file F.
    #[debug(skip)]
    raw_size: [u8; 3],

    /// Used to track the state of the file throughout the life of the file from creation to deletion.
    #[getset(get = "pub")]
    #[br(assert(!state.invalid(), FfsLibError::EndOfFv))]
    state: FileState,

    /// The length of the file in bytes, including the FFS header.
    #[br(parse_with(parse_size), args(attributes, raw_size))]
    #[bw(write_with(write_size), args(attributes))]
    #[getset(get_copy = "pub")]
    #[debug(format = "{0:} | {0:#X}")]
    size: usize,
}

impl FileHdr {
    pub const HDR_CHECKSUM_OFFSET: usize = 16;
    pub const DATA_CHECKSUM_OFFSET: usize = 17;
    pub const STATE_CHECKSUM_OFFSET: usize = 23;
    pub const MIN_HDR_LENGTH: usize = 24;
}

#[binrw::parser(reader, endian)]
fn parse_size(attr: FileAttribute, raw_size: [u8; 3]) -> BinResult<usize> {
    if attr.large_file() {
        Ok(u64::read_options(reader, endian, ())? as usize)
    } else {
        if endian == Endian::Little {
            Ok(u32::from_le_bytes([raw_size[0], raw_size[1], raw_size[2], 0]) as usize)
        } else {
            Ok(u32::from_be_bytes([0, raw_size[0], raw_size[1], raw_size[2]]) as usize)
        }
    }
}

#[binrw::writer(writer, endian)]
fn write_size(size: &usize, attr: &FileAttribute) -> BinResult<()> {
    if attr.large_file() {
        let data = *size as u64;
        data.write_options(writer, endian, ())?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileType {
    ALL = 0x00,
    RAW = 0x01,
    FREEFORM = 0x02,
    SECURITY_CORE = 0x03,
    PEI_CORE = 0x04,
    DXE_CORE = 0x05,
    PEIM = 0x06,
    DRIVER = 0x07,
    COMBINED_PEIM_DRIVER = 0x08,
    APPLICATION = 0x09,
    MM = 0x0A,
    FIRMWARE_VOLUME_IMAGE = 0x0B,
    COMBINED_MM_DXE = 0x0C,
    MM_CORE = 0x0D,
    MM_STANDALONE = 0x0E,
    MM_CORE_STANDALONE = 0x0F,
    OEM(u8),
    DEBUG(u8),
    FFS_PAD = 0xF0,
    Invalid = 0xFF,
}

impl FileType {
    pub fn is_sectioned(&self) -> bool {
        if let FileType::APPLICATION
        | FileType::COMBINED_PEIM_DRIVER
        | FileType::COMBINED_MM_DXE
        | FileType::DRIVER
        | FileType::DXE_CORE
        | FileType::FIRMWARE_VOLUME_IMAGE
        | FileType::FREEFORM
        | FileType::PEIM
        | FileType::PEI_CORE
        | FileType::MM
        | FileType::MM_CORE
        | FileType::MM_STANDALONE = self
        {
            true
        } else {
            false
        }
    }
}

impl TryFrom<u8> for FileType {
    type Error = FfsLibError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(FileType::ALL),
            0x01 => Ok(FileType::RAW),
            0x02 => Ok(FileType::FREEFORM),
            0x03 => Ok(FileType::SECURITY_CORE),
            0x04 => Ok(FileType::PEI_CORE),
            0x05 => Ok(FileType::DXE_CORE),
            0x06 => Ok(FileType::PEIM),
            0x07 => Ok(FileType::DRIVER),
            0x08 => Ok(FileType::COMBINED_PEIM_DRIVER),
            0x09 => Ok(FileType::APPLICATION),
            0x0A => Ok(FileType::MM),
            0x0B => Ok(FileType::FIRMWARE_VOLUME_IMAGE),
            0x0C => Ok(FileType::COMBINED_MM_DXE),
            0x0D => Ok(FileType::MM_CORE),
            0x0E => Ok(FileType::MM_STANDALONE),
            0x0F => Ok(FileType::MM_CORE_STANDALONE),
            0xF0 => Ok(FileType::FFS_PAD),
            0xC0..=0xDF => Ok(FileType::OEM(value)),
            0xE0..=0xEF => Ok(FileType::DEBUG(value)),
            0xFF => Ok(FileType::Invalid),
            _ => Err(FfsLibError::UnexpectedEnumValue {
                name: format!("{}:FileType", module_path!()),
                got: Box::new(value),
            }),
        }
    }
}

impl Into<u8> for FileType {
    fn into(self) -> u8 {
        match self {
            FileType::ALL => 0x00,
            FileType::RAW => 0x01,
            FileType::FREEFORM => 0x02,
            FileType::SECURITY_CORE => 0x03,
            FileType::PEI_CORE => 0x04,
            FileType::DXE_CORE => 0x05,
            FileType::PEIM => 0x06,
            FileType::DRIVER => 0x07,
            FileType::COMBINED_PEIM_DRIVER => 0x08,
            FileType::APPLICATION => 0x09,
            FileType::MM => 0x0A,
            FileType::FIRMWARE_VOLUME_IMAGE => 0x0B,
            FileType::COMBINED_MM_DXE => 0x0C,
            FileType::MM_CORE => 0x0D,
            FileType::MM_STANDALONE => 0x0E,
            FileType::MM_CORE_STANDALONE => 0x0F,
            FileType::FFS_PAD => 0xf0,
            FileType::DEBUG(val) => val,
            FileType::OEM(val) => val,
            FileType::Invalid => 0xFF,
        }
    }
}

impl BinRead for FileType {
    type Args<'a> = ();
    fn read_options<R: std::io::prelude::Read + std::io::prelude::Seek>(
        reader: &mut R,
        _: binrw::Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let mut buf = [0u8; 1];
        let pos = reader.stream_position()?;
        reader.read_exact(&mut buf)?;

        Ok(FileType::try_from(buf[0]).map_err(|e| e.into_binrw_err(pos))?)
    }
}

impl BinWrite for FileType {
    type Args<'a> = ();
    fn write_options<W: std::io::prelude::Write + std::io::prelude::Seek>(
        &self,
        writer: &mut W,
        _: binrw::Endian,
        _: Self::Args<'_>,
    ) -> BinResult<()> {
        let data: u8 = (*self).into();
        writer.write(&[data])?;
        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileAttribute {
    data: u8,
}

impl FileAttribute {
    const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
    const FFS_ATTRIB_DATA_ALIGNMENT_2: u8 = 0x02;
    const FFS_ATTRIB_FIXED: u8 = 0x04;
    const FFS_ATTRIB_DATA_ALIGNMENT: u8 = 0x38;
    const FFS_ATTRIB_CHECKSUM: u8 = 0x40;

    pub fn large_file(&self) -> bool {
        self.data & Self::FFS_ATTRIB_LARGE_FILE != 0
    }
    pub fn set_large_file(&mut self, val: bool) {
        if val {
            self.data |= Self::FFS_ATTRIB_LARGE_FILE;
        } else {
            self.data &= !Self::FFS_ATTRIB_LARGE_FILE;
        }
    }

    /// Get FFS alignment accordance of UEFI PI spec
    /// Vol. 3 ch. 3.2.3
    pub fn alignment(&self) -> Result<usize, FfsLibError> {
        let align_val = self.data & Self::FFS_ATTRIB_DATA_ALIGNMENT >> 3;
        if self.data & Self::FFS_ATTRIB_DATA_ALIGNMENT == 0 {
            match align_val {
                0 => Ok(1),
                1 => Ok(16),
                2 => Ok(128),
                3 => Ok(512),
                // 1 kib
                4 => Ok(1024),
                // 4 kib
                5 => Ok(4 * 1024),
                // 32 kib
                6 => Ok(32 * 1024),
                // 64 kib
                7 => Ok(64 * 1024),
                _ => Err(FfsLibError::UnexpectedEnumValue {
                    name: format!("File alignment (alignment2 = 0)"),
                    got: Box::new(align_val),
                }),
            }
        } else {
            match align_val {
                // 128 kib
                0 => Ok(128 * 1024),
                // 256 kib
                1 => Ok(256 * 1024),
                // 512 kib
                2 => Ok(512 * 1024),
                // 1 mib
                3 => Ok(1024 * 1024),
                // 2 mib
                4 => Ok(2 * 1024 * 1024),
                // 4 mib
                5 => Ok(4 * 1024 * 1024),
                // 8 mib
                6 => Ok(8 * 1024 * 1024),
                // 16 mib
                7 => Ok(16 * 1024 * 1024),
                _ => Err(FfsLibError::UnexpectedEnumValue {
                    name: format!("File alignment (alignment2 = 1)"),
                    got: Box::new(align_val),
                }),
            }
        }
    }

    pub fn file_checksum(&self) -> bool {
        self.data & Self::FFS_ATTRIB_CHECKSUM != 0
    }

    pub fn fixed(&self) -> bool {
        self.data & Self::FFS_ATTRIB_FIXED != 0
    }
}

impl Debug for FileAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0:} | {0:#X} | ", self.data)?;
        if self.large_file() {
            write!(f, "LARGE ")?;
        }
        if self.file_checksum() {
            write!(f, "CHECKSUM ")?;
        }
        if self.fixed() {
            write!(f, "FIXED ")?;
        }
        if let Ok(ali) = self.alignment() {
            write!(f, "Alignment({0:} | {0:#X})", ali)?;
        }
        write!(f, "")
    }
}

#[binrw]
#[brw(little)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileState {
    data: u8,
}

impl FileState {
    const EFI_FILE_HEADER_CONSTRUCTION: u8 = 0x01;
    const EFI_FILE_HEADER_VALID: u8 = 0x02;
    const EFI_FILE_DATA_VALID: u8 = 0x04;
    const EFI_FILE_MARKED_FOR_UPDATE: u8 = 0x08;
    const EFI_FILE_DELETED: u8 = 0x10;
    const EFI_FILE_HEADER_INVALID: u8 = 0x20;
    pub fn header_construction(&self) -> bool {
        self.data & Self::EFI_FILE_HEADER_CONSTRUCTION != 0
    }
    pub fn header_valid(&self) -> bool {
        self.data & Self::EFI_FILE_HEADER_VALID != 0
    }
    pub fn data_valid(&self) -> bool {
        self.data & Self::EFI_FILE_DATA_VALID != 0
    }
    pub fn marked_for_update(&self) -> bool {
        self.data & Self::EFI_FILE_MARKED_FOR_UPDATE != 0
    }
    pub fn deleted(&self) -> bool {
        self.data & Self::EFI_FILE_DELETED != 0
    }
    pub fn header_invalid(&self) -> bool {
        self.data & Self::EFI_FILE_HEADER_INVALID != 0
    }
    pub fn invalid(&self) -> bool {
        self.header_invalid() && self.header_valid()
    }
}

impl Debug for FileState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0:} | {0:#X} | ", self.data)?;
        if self.header_construction() {
            write!(f, "HEADER_CONSTRUCTION ")?;
        }
        if self.header_valid() {
            write!(f, "HEADER_VALID ")?;
        }
        if self.data_valid() {
            write!(f, "DATA_VALID ")?;
        }
        if self.marked_for_update() {
            write!(f, "MARKED_FOR_UPDATE ")?;
        }
        if self.deleted() {
            write!(f, "DELETED ")?;
        }
        if self.header_invalid() {
            write!(f, "HEADER_INVALID ")?;
        }
        write!(f, "")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_file() -> anyhow::Result<()> {
        let raw_data = std::fs::read("test/0A66E322-3740-4cce-AD62-BD172CECCA35.ffs")?;
        let mut cursor = Cursor::new(raw_data.as_slice());
        let ffs = File::read(&mut cursor)?;

        let mut write_buf = vec![];
        let mut write_cursor = Cursor::new(&mut write_buf);
        ffs.write(&mut write_cursor)?;
        assert_eq!(raw_data.len(), write_buf.len());
        assert!(raw_data.eq(&write_buf));
        Ok(())
    }
}
