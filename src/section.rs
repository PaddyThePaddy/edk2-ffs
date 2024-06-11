use std::{
    cell::RefCell,
    io::{Cursor, Seek, SeekFrom, Write},
    rc::Rc,
};

use binrw::{binread, binrw, BinRead, BinResult, BinWrite, Endian};
use getset::{Getters, MutGetters};
use uuid::Uuid;

use crate::{
    read_rc_refcell, read_remaining_length, read_remaining_length_rc_refcell, write_rc_refcell,
    write_vec_rc_refcell, FfsLibError, Fv, UuidBytes,
};

#[binread]
#[br(little)]
#[derive(Debug, Clone, Getters, MutGetters)]
pub struct Section {
    #[brw(align_before(4))]
    #[getset(get = "pub", get_mut = "pub")]
    hdr: SectionHdr,
    #[br(args(hdr._type, hdr.size -
        if hdr.using_extended_size() {
            8
        } else {
            4
        }))]
    #[getset(get = "pub", get_mut = "pub")]
    payload: SectionPayload,
}

impl BinWrite for Section {
    type Args<'a> = (u64,);
    fn write_options<W: std::io::Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: (u64,),
    ) -> BinResult<()> {
        let start_pos = writer.stream_position()? - args.0;
        if start_pos % 4 != 0 {
            for _ in 0..4 - (start_pos % 4) {
                [0u8].write_options(writer, endian, ())?;
            }
        }
        let mut hdr_buf = Vec::with_capacity(SectionHdr::MIN_HDR_LENGTH);
        let mut hdr_buf_cursor = Cursor::new(&mut hdr_buf);
        let mut payload_buf = Vec::with_capacity(self.hdr().size - SectionHdr::MIN_HDR_LENGTH);
        let mut payload_buf_cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut payload_buf);
        self.hdr.write_options(&mut hdr_buf_cursor, endian, ())?;
        self.payload.write_options(
            &mut payload_buf_cursor,
            endian,
            (self.hdr.size - if self.hdr.using_extended_size() { 8 } else { 4 },),
        )?;
        let mut total_len = hdr_buf_cursor.position() + payload_buf_cursor.position();
        let requires_extended_size = self.hdr.using_extended_size() || total_len >= (1 << 24);
        if requires_extended_size {
            if !self.hdr.using_extended_size() {
                hdr_buf_cursor.seek(SeekFrom::Start(start_pos))?;
                hdr_buf_cursor.write_all(&[0xFF, 0xFF, 0xFF])?;
                total_len += 4;
            }
            hdr_buf_cursor.seek(SeekFrom::Start(4))?;
            (total_len as u32).write_options(&mut hdr_buf_cursor, endian, ())?;
        } else {
            let length_bytes = total_len.to_le_bytes();
            hdr_buf_cursor.seek(SeekFrom::Start(0))?;
            length_bytes[..3].write_options(&mut hdr_buf_cursor, endian, ())?;
        }

        hdr_buf.write_options(writer, endian, ())?;
        payload_buf.write_options(writer, endian, ())?;
        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(custom_debug::Debug, Clone, Getters)]
pub struct SectionHdr {
    /// A 24-bit unsigned integer that contains the total size of the section in bytes,
    /// including the EFI_COMMON_SECTION_HEADER.
    #[debug(skip)]
    raw_size: [u8; 3],

    /// Declares the section type.
    _type: SectionType,
    #[br(parse_with(parse_size), args(raw_size))]
    #[bw(write_with(write_size), args(raw_size))]
    #[debug(format = "{0:} | {0:#X}")]
    size: usize,
}

impl SectionHdr {
    pub const MIN_HDR_LENGTH: usize = 4;
    pub fn using_extended_size(&self) -> bool {
        self.raw_size[0] == 0xFF && self.raw_size[1] == 0xFF && self.raw_size[2] == 0xFF
    }

    pub fn get_type(&self) -> SectionType {
        self._type
    }
}

#[binrw::parser(reader, endian)]
fn parse_size(raw_size: [u8; 3]) -> BinResult<usize> {
    if raw_size[0] == 0xFF && raw_size[1] == 0xFF && raw_size[2] == 0xFF {
        Ok(u32::read_options(reader, endian, ())? as usize)
    } else {
        if endian == Endian::Little {
            Ok(u32::from_le_bytes([raw_size[0], raw_size[1], raw_size[2], 0]) as usize)
        } else {
            Ok(u32::from_be_bytes([0, raw_size[0], raw_size[1], raw_size[2]]) as usize)
        }
    }
}

#[binrw::writer(writer, endian)]
fn write_size(size: &usize, raw_size: &[u8; 3]) -> BinResult<()> {
    if raw_size[0] == 0xFF && raw_size[1] == 0xFF && raw_size[2] == 0xFF {
        let data = *size as u32;
        data.write_options(writer, endian, ())?;
    }
    Ok(())
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    ALL = 0x0,
    /// An encapsulation section type in which the
    /// section data is compressed.
    COMPRESSION = 0x01,
    /// The leaf section which is encapsulation defined by specific GUID.
    GUID_DEFINED = 0x02,
    /// An encapsulation section type in which the section data is disposable.
    /// A disposable section is an encapsulation section in which the section data may be disposed of during
    /// the process of creating or updating a firmware image without significant impact on the usefulness of
    /// the file. The Type field in the section header is set to EFI_SECTION_DISPOSABLE. This
    /// allows optional or descriptive data to be included with the firmware file which can be removed in
    /// order to conserve space. The contents of this section are implementation specific, but might contain
    /// debug data or detailed integration instructions.
    DISPOSABLE = 0x03,
    /// The leaf section which contains PE32+ image.
    PE32 = 0x10,
    /// A leaf section type that contains a position-independent-code (PIC) image.
    /// A PIC image section is a leaf section that contains a position-independent-code (PIC) image.
    /// In addition to normal PE32+ images that contain relocation information, PEIM executables may be
    /// PIC and are referred to as PIC images. A PIC image is the same as a PE32+ image except that all
    /// relocation information has been stripped from the image and the image can be moved and will
    /// execute correctly without performing any relocation or other fix-ups. EFI_PIC_SECTION2 must
    /// be used if the section is 16MB or larger.
    PIC = 0x11,
    /// The leaf section which constains the position-independent-code image.
    TE = 0x12,
    DXE_DEPEX = 0x13,
    /// The leaf section which contains a numeric build number and
    /// an optional unicode string that represents the file revision.
    VERSION = 0x14,
    /// The leaf section which contains a unicode string that
    /// is human readable file name.
    USER_INTERFACE = 0x15,
    /// Leaf section type that contains an
    /// IA-32 16-bit executable image.
    COMPATIBILITY16 = 0x16,
    /// The leaf section which contains a PI FV.
    FIRMWARE_VOLUME_IMAGE = 0x17,
    /// The leaf section which contains a single GUID.
    FREEFORM_SUBTYPE_GUID = 0x18,
    /// The leaf section which contains an array of zero or more bytes.
    RAW = 0x19,
    /// The leaf section used to determine the dispatch order of PEIMs.
    PEI_DEPEX = 0x1B,
    /// The SMM dependency expression section is a leaf section that contains a dependency expression that
    /// is used to determine the dispatch order for SMM drivers. Before the SMRAM invocation of the
    /// SMM driver's entry point, this dependency expression must evaluate to TRUE. See the Platform
    /// Initialization Specification, Volume 2, for details regarding the format of the dependency expression.
    /// The dependency expression may refer to protocols installed in either the UEFI or the SMM protocol
    /// database. EFI_SMM_DEPEX_SECTION2 must be used if the section is 16MB or larger.
    MM_DEPEX = 0x1C,
}

impl TryFrom<u8> for SectionType {
    type Error = FfsLibError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SectionType::ALL),
            0x01 => Ok(SectionType::COMPRESSION),
            0x02 => Ok(SectionType::GUID_DEFINED),
            0x03 => Ok(SectionType::DISPOSABLE),
            0x10 => Ok(SectionType::PE32),
            0x11 => Ok(SectionType::PIC),
            0x12 => Ok(SectionType::TE),
            0x13 => Ok(SectionType::DXE_DEPEX),
            0x14 => Ok(SectionType::VERSION),
            0x15 => Ok(SectionType::USER_INTERFACE),
            0x16 => Ok(SectionType::COMPATIBILITY16),
            0x17 => Ok(SectionType::FIRMWARE_VOLUME_IMAGE),
            0x18 => Ok(SectionType::FREEFORM_SUBTYPE_GUID),
            0x19 => Ok(SectionType::RAW),
            0x1B => Ok(SectionType::PEI_DEPEX),
            0x1C => Ok(SectionType::MM_DEPEX),
            _ => Err(FfsLibError::UnexpectedEnumValue {
                name: "SectionType".to_string(),
                got: Box::new(value),
            }),
        }
    }
}

impl Into<u8> for SectionType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl BinRead for SectionType {
    type Args<'a> = ();
    fn read_options<R: std::io::prelude::Read + std::io::prelude::Seek>(
        reader: &mut R,
        _: binrw::Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let mut buf = [0u8; 1];
        let pos = reader.stream_position()?;
        reader.read_exact(&mut buf)?;

        Ok(SectionType::try_from(buf[0]).map_err(|e| e.into_binrw_err(pos))?)
    }
}

impl BinWrite for SectionType {
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
#[br(import(_type: SectionType, length:usize))]
#[bw(import(length:usize))]
#[derive(custom_debug::Debug, Clone)]
pub enum SectionPayload {
    /// An encapsulation section type in which the
    /// section data is compressed.
    #[br(pre_assert(_type == SectionType::COMPRESSION) )]
    COMPRESSION {
        /// The UINT32 that indicates the size of the section data after decompression.
        uncompressed_length: u32,
        /// Indicates which compression algorithm is used.
        compression_type: CompressionType,
        #[br(parse_with(parse_compressed_section), args(length - 5 as usize, uncompressed_length as usize, compression_type))]
        #[bw(write_with(write_compressed_section), args(*uncompressed_length as usize, *compression_type))]
        data: Vec<Rc<RefCell<Section>>>,
    },
    /// The leaf section which is encapsulation defined by specific GUID.
    #[br(pre_assert(_type == SectionType::GUID_DEFINED) )]
    GUID_DEFINED {
        /// The GUID that defines the format of the data that follows. It is a vendor-defined section type.
        definition: UuidBytes,
        /// Contains the offset in bytes from the beginning of the common header to the first byte of the data.
        data_offset: u16,
        /// The bit field that declares some specific characteristics of the section contents.
        attributes: GuidDefinedAttribute,
        #[br(args(length - 20, definition, data_offset, attributes))]
        #[bw(args(definition, data_offset, attributes))]
        data: GuidDefinedData,
    },
    /// An encapsulation section type in which the section data is disposable.
    /// A disposable section is an encapsulation section in which the section data may be disposed of during
    /// the process of creating or updating a firmware image without significant impact on the usefulness of
    /// the file. The Type field in the section header is set to EFI_SECTION_DISPOSABLE. This
    /// allows optional or descriptive data to be included with the firmware file which can be removed in
    /// order to conserve space. The contents of this section are implementation specific, but might contain
    /// debug data or detailed integration instructions.
    #[br(pre_assert(_type == SectionType::DISPOSABLE) )]
    DISPOSABLE {
        #[br(parse_with(read_remaining_length_rc_refcell), args(length, ()))]
        #[bw(write_with(write_vec_rc_refcell))]
        image: Vec<Rc<RefCell<Section>>>,
    },
    /// The leaf section which contains PE32+ image.
    #[br(pre_assert(_type == SectionType::PE32) )]
    PE32 {
        #[br(count(length))]
        #[debug(skip)]
        image: Vec<u8>,
    },
    /// A leaf section type that contains a position-independent-code (PIC) image.
    /// A PIC image section is a leaf section that contains a position-independent-code (PIC) image.
    /// In addition to normal PE32+ images that contain relocation information, PEIM executables may be
    /// PIC and are referred to as PIC images. A PIC image is the same as a PE32+ image except that all
    /// relocation information has been stripped from the image and the image can be moved and will
    /// execute correctly without performing any relocation or other fix-ups. EFI_PIC_SECTION2 must
    /// be used if the section is 16MB or larger.
    #[br(pre_assert(_type == SectionType::PIC) )]
    PIC {
        #[br(count(length))]
        #[debug(skip)]
        image: Vec<u8>,
    },
    /// The leaf section which constains the position-independent-code image.
    #[br(pre_assert(_type == SectionType::TE) )]
    TE {
        #[br(count(length))]
        #[debug(skip)]
        image: Vec<u8>,
    },
    /// The leaf section which could be used to determine the dispatch order of DXEs.
    #[br(pre_assert(_type == SectionType::DXE_DEPEX))]
    DXE_DEPEX(#[br(args(length))] Depex),
    /// The leaf section which contains a numeric build number and
    /// an optional unicode string that represents the file revision.
    #[br(pre_assert(_type == SectionType::VERSION) )]
    VERSION {
        buildn_umber: u16,
        /// Array of unicode string.
        #[br(parse_with(parse_utf16_string), args(length - 2))]
        #[bw(write_with(write_utf16_string), args(length - 2))]
        version_str: String,
    },
    /// The leaf section which contains a unicode string that
    /// is human readable file name.
    #[br(pre_assert(_type == SectionType::USER_INTERFACE) )]
    USER_INTERFACE {
        /// Array of unicode string.
        #[br(parse_with(parse_utf16_string), args(length))]
        #[bw(write_with(write_utf16_string), args(length))]
        filename: String,
    },
    /// Leaf section type that contains an
    /// IA-32 16-bit executable image.
    #[br(pre_assert(_type == SectionType::COMPATIBILITY16) )]
    COMPATIBILITY16 {
        #[br(count(length))]
        #[debug(skip)]
        image: Vec<u8>,
    },
    /// The leaf section which contains a PI FV.
    #[br(pre_assert(_type == SectionType::FIRMWARE_VOLUME_IMAGE))]
    FIRMWARE_VOLUME_IMAGE {
        #[bw(write_with(write_rc_refcell))]
        #[br(parse_with(read_rc_refcell))]
        fv: Rc<RefCell<Fv>>,
    },
    /// The leaf section which contains a single GUID.
    #[br(pre_assert(_type == SectionType::FREEFORM_SUBTYPE_GUID) )]
    FREEFORM_SUBTYPE_GUID {
        /// This GUID is defined by the creator of the file. It is a vendor-defined file type.
        subtype: UuidBytes,
        #[br(count(length - 16))]
        #[debug(skip)]
        data: Vec<u8>,
    },
    /// The leaf section which contains an array of zero or more bytes.
    #[br(pre_assert(_type == SectionType::RAW) )]
    RAW {
        #[br(count(length))]
        #[debug(skip)]
        data: Vec<u8>,
    },
    /// The leaf section used to determine the dispatch order of PEIMs.
    #[br(pre_assert(_type == SectionType::PEI_DEPEX))]
    PEI_DEPEX(#[br(args(length))] Depex),
    /// The SMM dependency expression section is a leaf section that contains a dependency expression that
    /// is used to determine the dispatch order for SMM drivers. Before the SMRAM invocation of the
    /// SMM driver's entry point, this dependency expression must evaluate to TRUE. See the Platform
    /// Initialization Specification, Volume 2, for details regarding the format of the dependency expression.
    /// The dependency expression may refer to protocols installed in either the UEFI or the SMM protocol
    /// database. EFI_SMM_DEPEX_SECTION2 must be used if the section is 16MB or larger.
    #[br(pre_assert(_type == SectionType::MM_DEPEX))]
    MM_DEPEX(#[br(args(length))] Depex),
}

#[binrw::parser(reader, endian)]
fn parse_utf16_string(length: usize) -> BinResult<String> {
    let start_pos = reader.stream_position()?;
    let u16_buf: Vec<u16> = read_remaining_length(reader, endian, (length, ()))?;
    String::from_utf16(&u16_buf).map_err(|_| binrw::Error::Custom {
        pos: start_pos,
        err: Box::new("Decode UTF16 failed".to_string()),
    })
}

#[binrw::writer(writer, endian)]
fn write_utf16_string(s: &String, length: usize) -> BinResult<()> {
    let mut buf = s.encode_utf16().collect::<Vec<u16>>();
    while buf.len() * 2 < length {
        buf.push(0);
    }
    buf.write_options(writer, endian, ())?;
    Ok(())
}

#[binrw::parser(reader, endian)]
fn parse_compressed_section(
    data_length: usize,
    _: usize,
    compression_type: CompressionType,
) -> BinResult<Vec<Rc<RefCell<Section>>>> {
    let mut buf = vec![0u8; data_length];
    let start_pos = reader.stream_position()?;
    reader.read(&mut buf)?;
    if compression_type == CompressionType::StandardCompression {
        buf = edk2_guid_process_sys::efi_dec(&buf).map_err(|e| binrw::Error::Custom {
            pos: start_pos,
            err: Box::new(format!("EFI decompression error code: {e}")),
        })?;
    }
    let mut compressed_data_reader = Cursor::new(buf.as_slice());
    let inner_sections: Vec<Rc<RefCell<Section>>> =
        read_remaining_length_rc_refcell(&mut compressed_data_reader, endian, (buf.len(), ()))?;
    Ok(inner_sections)
}

#[binrw::writer(writer, endian)]
fn write_compressed_section(
    data: &Vec<Rc<RefCell<Section>>>,
    _: usize,
    compression_type: CompressionType,
) -> BinResult<()> {
    let start_pos = writer.stream_position()?;
    if compression_type == CompressionType::StandardCompression {
        let mut buf = vec![];
        let mut buf_writer = Cursor::new(&mut buf);
        write_vec_rc_refcell(&data, &mut buf_writer, endian, ((0,),))?;
        edk2_guid_process_sys::efi_enc(&buf)
            .map_err(|e| binrw::Error::Custom {
                pos: start_pos,
                err: Box::new(format!("EFI compression error code: {e}")),
            })?
            .write_options(writer, endian, ())?;
    } else {
        write_vec_rc_refcell(&data, writer, endian, ((0,),))?;
    }
    Ok(())
}

#[derive(custom_debug::Debug, Clone)]
pub enum GuidDefinedData {
    Processed(Vec<Rc<RefCell<Section>>>),
    Unknown(#[debug(skip)] Vec<u8>),
}

impl GuidDefinedData {
    const LZMA: Uuid = uuid::uuid!("ee4e5898-3914-4259-9d6e-dc7bd79403cf");
    const LZMAF86: Uuid = uuid::uuid!("d42ae6bd-1352-4bfb-909a-ca72a6eae889");
    const TIANO: Uuid = uuid::uuid!("a31280ad-481e-41b6-95e8-127f4c984779");
    const CRC32: Uuid = uuid::uuid!("fc1bcdb0-7d31-49aa-936a-a4600d9dd083");
    const BROTLI: Uuid = uuid::uuid!("3d532050-5cda-4fd0-879e-0f7f630d5afb");
}

impl BinRead for GuidDefinedData {
    type Args<'a> = (usize, UuidBytes, u16, GuidDefinedAttribute);
    fn read_options<'a, R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'a>,
    ) -> BinResult<Self> {
        let start_pos = reader.stream_position()?;
        let data: Vec<u8> = read_remaining_length(reader, endian, (args.0, ()))?;
        if !args.3.is_procession_required() {
            return Ok(GuidDefinedData::Unknown(data));
        }
        let sections;
        match args.1.as_ref() {
            &Self::LZMA => {
                let dec_data = edk2_guid_process_sys::lzma_dec(&data, false).map_err(|e| {
                    binrw::Error::Custom {
                        pos: start_pos,
                        err: Box::new(format!("LZMA decompression error code: {e}")),
                    }
                })?;
                let mut buf_cursor = Cursor::new(&dec_data);
                sections = read_remaining_length_rc_refcell(
                    &mut buf_cursor,
                    endian,
                    (dec_data.len(), ()),
                )?;
            }
            &Self::LZMAF86 => {
                let dec_data = edk2_guid_process_sys::lzma_dec(&data, true).map_err(|e| {
                    binrw::Error::Custom {
                        pos: start_pos,
                        err: Box::new(format!("LZMAF86 decompression error code: {e}")),
                    }
                })?;
                let mut buf_cursor = Cursor::new(&dec_data);
                sections = read_remaining_length_rc_refcell(
                    &mut buf_cursor,
                    endian,
                    (dec_data.len(), ()),
                )?;
            }
            &Self::TIANO => {
                let dec_data =
                    edk2_guid_process_sys::tiano_dec(&data).map_err(|e| binrw::Error::Custom {
                        pos: start_pos,
                        err: Box::new(format!("TIANO decompression error code: {e}")),
                    })?;
                let mut buf_cursor = Cursor::new(&dec_data);
                sections = read_remaining_length_rc_refcell(
                    &mut buf_cursor,
                    endian,
                    (dec_data.len(), ()),
                )?;
            }
            &Self::CRC32 => {
                let dec_data =
                    edk2_guid_process_sys::crc32_dec(&data).map_err(|e| binrw::Error::Custom {
                        pos: start_pos,
                        err: Box::new(format!("CRC32 decode error: {e}")),
                    })?;
                let mut buf_cursor = Cursor::new(&dec_data);
                sections = read_remaining_length_rc_refcell(
                    &mut buf_cursor,
                    endian,
                    (dec_data.len(), ()),
                )?;
            }
            &Self::BROTLI => {
                let dec_data =
                    edk2_guid_process_sys::brotli_dec(&data).map_err(|e| binrw::Error::Custom {
                        pos: start_pos,
                        err: Box::new(format!("Brotli decode error: {e}")),
                    })?;
                let mut buf_cursor = Cursor::new(&dec_data);
                sections = read_remaining_length_rc_refcell(
                    &mut buf_cursor,
                    endian,
                    (dec_data.len(), ()),
                )?;
            }
            _ => return Err(binrw::Error::NoVariantMatch { pos: start_pos }),
        }
        Ok(GuidDefinedData::Processed(sections))
    }
}

impl BinWrite for GuidDefinedData {
    type Args<'a> = (&'a UuidBytes, &'a u16, &'a GuidDefinedAttribute);
    fn write_options<'a, W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'a>,
    ) -> BinResult<()> {
        let start_pos = writer.stream_position()?;
        match self {
            GuidDefinedData::Unknown(raw) => {
                raw.write_options(writer, endian, ())?;
            }
            GuidDefinedData::Processed(sections) => {
                let mut raw_buf = vec![];
                let mut raw_cursor = Cursor::new(&mut raw_buf);
                write_vec_rc_refcell(sections, &mut raw_cursor, endian, ((0,),))?;
                match args.0.as_ref() {
                    &Self::LZMA => {
                        let enc_data =
                            edk2_guid_process_sys::lzma_enc(&raw_buf, false).map_err(|e| {
                                binrw::Error::Custom {
                                    pos: start_pos,
                                    err: Box::new(format!("LZMA compression error code: {e}")),
                                }
                            })?;
                        enc_data.write_options(writer, endian, ())?;
                    }
                    &Self::LZMAF86 => {
                        let enc_data =
                            edk2_guid_process_sys::lzma_enc(&raw_buf, true).map_err(|e| {
                                binrw::Error::Custom {
                                    pos: start_pos,
                                    err: Box::new(format!("LZMA compression error code: {e}")),
                                }
                            })?;
                        enc_data.write_options(writer, endian, ())?;
                    }
                    &Self::TIANO => {
                        let enc_data = edk2_guid_process_sys::tiano_enc(&raw_buf).map_err(|e| {
                            binrw::Error::Custom {
                                pos: start_pos,
                                err: Box::new(format!("LZMA compression error code: {e}")),
                            }
                        })?;
                        enc_data.write_options(writer, endian, ())?;
                    }
                    &Self::CRC32 => {
                        let enc_data = edk2_guid_process_sys::crc32_enc(&raw_buf).map_err(|e| {
                            binrw::Error::Custom {
                                pos: start_pos,
                                err: Box::new(format!("CRC32 encode error: {e}")),
                            }
                        })?;
                        enc_data.write_options(writer, endian, ())?;
                    }
                    &Self::BROTLI => {
                        let enc_data =
                            edk2_guid_process_sys::brotli_enc(&raw_buf).map_err(|e| {
                                binrw::Error::Custom {
                                    pos: start_pos,
                                    err: Box::new(format!("Brotli encode error: {e}")),
                                }
                            })?;
                        enc_data.write_options(writer, endian, ())?;
                    }
                    _ => return Err(binrw::Error::NoVariantMatch { pos: start_pos }),
                }
            }
        }
        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    #[brw(magic(0u8))]
    NotCompressed = 0,
    #[brw(magic(1u8))]
    StandardCompression = 1,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuidDefinedAttribute {
    data: u16,
}

impl GuidDefinedAttribute {
    const EFI_GUIDED_SECTION_PROCESSING_REQUIRED: u16 = 0x01;
    const EFI_GUIDED_SECTION_AUTH_STATUS_VALID: u16 = 0x02;
    pub fn is_procession_required(&self) -> bool {
        self.data & Self::EFI_GUIDED_SECTION_PROCESSING_REQUIRED != 0
    }
    pub fn is_auth_status_valid(&self) -> bool {
        self.data & Self::EFI_GUIDED_SECTION_AUTH_STATUS_VALID != 0
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepexToken {
    #[brw(magic(0x0u8))]
    Before(UuidBytes),
    #[brw(magic(0x1u8))]
    After(UuidBytes),
    #[brw(magic(0x2u8))]
    Push(UuidBytes),
    #[brw(magic(0x3u8))]
    And,
    #[brw(magic(0x4u8))]
    Or,
    #[brw(magic(0x5u8))]
    Not,
    #[brw(magic(0x6u8))]
    True,
    #[brw(magic(0x7u8))]
    False,
    #[brw(magic(0x8u8))]
    End,
    #[brw(magic(0x9u8))]
    Sor,
}

#[binrw]
#[brw(little)]
#[br(import(remaining: usize))]
#[derive(Debug, Clone)]
pub struct Depex {
    #[br(parse_with=read_remaining_length, args(remaining, ()))]
    tokens: Vec<DepexToken>,
}

impl Depex {
    pub fn depex_expr(&self) -> Result<String, FfsLibError> {
        let mut expr_stack = vec![];
        let mut op_stack = vec![];
        let mut sor = false;
        for idx in 0..self.tokens.len() {
            match self.tokens[idx] {
                DepexToken::Before(guid) => {
                    if self.tokens.len() > 2 {
                        return Err(FfsLibError::InvalidInput(
                            "BEFORE should be the only opcode in the expression".to_string(),
                        ));
                    }
                    return Ok(format!("Before({guid})"));
                }
                DepexToken::After(guid) => {
                    if self.tokens.len() > 2 {
                        return Err(FfsLibError::InvalidInput(
                            "After should be the only opcode in the expression".to_string(),
                        ));
                    }
                    return Ok(format!("After({guid})"));
                }
                DepexToken::Push(guid) => {
                    expr_stack.push(guid.to_string());
                }
                DepexToken::And => {
                    let operand_2 =
                        get_next_operand(self.tokens[idx], &mut expr_stack, &mut op_stack)?;
                    let operand_1 =
                        get_next_operand(self.tokens[idx], &mut expr_stack, &mut op_stack)?;
                    expr_stack.push(format!("{operand_1} & {operand_2}"));
                }
                DepexToken::Or => {
                    let operand_2 =
                        get_next_operand(self.tokens[idx], &mut expr_stack, &mut op_stack)?;
                    let operand_1 =
                        get_next_operand(self.tokens[idx], &mut expr_stack, &mut op_stack)?;
                    expr_stack.push(format!("{operand_1} | {operand_2}"));
                }
                DepexToken::Not => {
                    let operand =
                        get_next_operand(self.tokens[idx], &mut expr_stack, &mut op_stack)?;
                    expr_stack.push(format!("!{operand}"));
                }
                DepexToken::True => {
                    expr_stack.push("True".to_string());
                }
                DepexToken::False => {
                    expr_stack.push("False".to_string());
                }
                DepexToken::End => {
                    if expr_stack.len() != 1 {
                        return Err(FfsLibError::InvalidInput(
                            "Error occurred when turning depex into infix expression".to_string(),
                        ));
                    } else {
                        if sor {
                            return Ok(format!(
                                "SOR {}",
                                expr_stack.pop().ok_or(FfsLibError::InvalidInput(
                                    "Depex expr stack runs out unexpectly".to_string()
                                ))?
                            ));
                        }
                        return expr_stack.pop().ok_or(FfsLibError::InvalidInput(
                            "Depex expr stack runs out unexpectly".to_string(),
                        ));
                    }
                }
                DepexToken::Sor => {
                    if idx != 0 {
                        return Err(FfsLibError::InvalidInput(
                            "SOR must be the first opcode in the depex expression".to_string(),
                        ));
                    }
                    sor = true;
                }
            }
            op_stack.push(self.tokens[idx]);
        }
        Err(FfsLibError::InvalidInput(
            "No End opcode in the depex token list".to_string(),
        ))
    }

    pub fn tokens(&self) -> &[DepexToken] {
        &self.tokens
    }
}

fn get_next_operand(
    current_op: DepexToken,
    expr_stack: &mut Vec<String>,
    op_stack: &mut Vec<DepexToken>,
) -> Result<String, FfsLibError> {
    let last_op = op_stack.pop().ok_or(FfsLibError::InvalidInput(
        "Depex op stack runs out unexpectly".to_string(),
    ))?;
    let last_expr = expr_stack.pop().ok_or(FfsLibError::InvalidInput(
        "Depex expr stack runs out unexpectly".to_string(),
    ))?;

    Ok(
        if let DepexToken::Push(_) | DepexToken::True | DepexToken::False = last_op {
            last_expr
        } else if last_op == current_op {
            last_expr
        } else {
            format!("({})", last_expr)
        },
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_section() -> anyhow::Result<()> {
        let buf = std::fs::read("test/9E21FD93-9C72-4c15-8C4B-E77F1DB2D792SEC1.guided")?;
        let mut reader = Cursor::new(&buf);
        let section = Section::read(&mut reader)?;
        let mut write_buf = vec![];
        let mut write_cursor = Cursor::new(&mut write_buf);
        section.write_options(&mut write_cursor, Endian::Little, (0,))?;
        assert_eq!(buf.len(), write_buf.len());
        if !write_buf.eq(&buf) {
            for i in 0..buf.len() {
                if buf[i] != write_buf[i] {
                    panic!("diff at {i:#X}");
                }
            }
        }
        assert!(write_buf.eq(&buf));
        Ok(())
    }
}
