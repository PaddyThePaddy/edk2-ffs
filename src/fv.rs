use crate::{buf_fmt, read_remaining_length, Checksum16, FfsLibError, File, UuidBytes};
use binrw::{
    binrw,
    meta::{EndianKind, ReadEndian},
    BinRead, BinResult, BinWrite, Endian,
};
use getset::{CopyGetters, Getters, MutGetters};
use std::{
    cell::RefCell,
    fmt::Debug,
    io::{Cursor, SeekFrom},
    num::Wrapping,
    rc::Rc,
};
use uuid::Uuid;

/// Represents EFI_FIRMWARE_VOLUME_HEADER defined in PI spec Vol. 3 Ch. 3.2.1.1
#[derive(custom_debug::Debug, Clone, Getters, MutGetters)]
pub struct Fv {
    #[getset(get = "pub", get_mut = "pub")]
    hdr: FvHdr,
    #[getset(get = "pub", get_mut = "pub")]
    ext_hdr: Option<FvExtHdr>,

    /// List of FFS file in the FV
    #[getset(get = "pub", get_mut = "pub")]
    files: Vec<Rc<RefCell<File>>>,
}

impl BinRead for Fv {
    type Args<'a> = ();
    fn read_options<R: std::io::prelude::Read + std::io::prelude::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: (),
    ) -> BinResult<Self> {
        let start_pos = reader.stream_position()?;
        let hdr = FvHdr::read_options(reader, endian, ())?;

        let ext_hdr = if hdr.ext_hdr_offset() != 0 {
            reader.seek(SeekFrom::Start(start_pos + hdr.ext_hdr_offset() as u64))?;
            Some(FvExtHdr::read_options(reader, endian, ())?)
        } else {
            None
        };
        reader.seek(SeekFrom::Start(start_pos + hdr.header_length() as u64))?;
        let mut files = vec![];
        while reader.stream_position()? - start_pos < hdr.fv_length() as u64 {
            match File::read_options(reader, endian, (start_pos,)) {
                Ok(ffs) => files.push(Rc::new(RefCell::new(ffs))),
                Err(e) => {
                    if let Some(FfsLibError::EndOfFv) = e.custom_err::<FfsLibError>() {
                        break;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        reader.seek(SeekFrom::Start(start_pos + hdr.fv_length() as u64))?;
        Ok(Self {
            hdr,
            ext_hdr,
            files,
        })
    }
}

impl BinWrite for Fv {
    type Args<'a> = ();
    fn write_options<W: std::io::prelude::Write + std::io::prelude::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> BinResult<()> {
        let start_pos = writer.stream_position()?;
        let mut out_buf = Vec::with_capacity(self.hdr().fv_length());
        let mut cursor = Cursor::new(&mut out_buf);

        self.hdr.write_options(&mut cursor, endian, ())?;
        //if let Some(ext_hdr) = self.ext_hdr() {
        //    ext_hdr.write_options(&mut cursor, endian, ())?;
        //}
        self.files
            .iter()
            .map(|e| {
                e.borrow()
                    .write_options(&mut cursor, endian, (self.hdr().attr().erase_polarity(),))
            })
            .collect::<Result<_, binrw::Error>>()?;
        out_buf.write_options(writer, endian, ())?;

        while writer.stream_position()? - start_pos < self.hdr.fv_length() as u64 {
            writer.write(if self.hdr().attr().erase_polarity() != 0 {
                &[0xffu8]
            } else {
                &[0u8]
            })?;
        }

        assert!(self.hdr().header_length() > FvHdr::CHECKSUM_OFFSET + 1);
        let mut hdr_checksum = Wrapping(0u16);
        let mut idx = 0;
        while idx + 1 < self.hdr().header_length() {
            hdr_checksum -= match endian {
                Endian::Big => u16::from_be_bytes([out_buf[idx], out_buf[idx + 1]]),
                Endian::Little => u16::from_le_bytes([out_buf[idx], out_buf[idx + 1]]),
            };
            idx += 2;
        }
        hdr_checksum += match endian {
            Endian::Big => u16::from_be_bytes([
                out_buf[FvHdr::CHECKSUM_OFFSET],
                out_buf[FvHdr::CHECKSUM_OFFSET + 1],
            ]),
            Endian::Little => u16::from_le_bytes([
                out_buf[FvHdr::CHECKSUM_OFFSET],
                out_buf[FvHdr::CHECKSUM_OFFSET + 1],
            ]),
        };
        let check_sum_bytes = match endian {
            Endian::Big => hdr_checksum.0.to_be_bytes(),
            Endian::Little => hdr_checksum.0.to_le_bytes(),
        };
        out_buf[FvHdr::CHECKSUM_OFFSET] = check_sum_bytes[0];
        out_buf[FvHdr::CHECKSUM_OFFSET + 1] = check_sum_bytes[1];

        Ok(())
    }
}

impl ReadEndian for Fv {
    const ENDIAN: EndianKind = EndianKind::Endian(Endian::Little);
}

#[binrw]
#[brw(little, magic = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")]
#[derive(Clone, Getters, CopyGetters, custom_debug::Debug)]
#[br(stream = stream, map_stream = Checksum16::new, assert(stream.check() == 0))]
pub struct FvHdr {
    /// Declares the file system with which the firmware volume is formatted.
    fs_guid: UuidBytes,

    /// Length in bytes of the complete firmware volume, including the header.
    #[br(map = |v: u64| v as usize)]
    #[bw(map = |v: &usize| *v as u64)]
    #[getset(get_copy = "pub")]
    #[debug(format = "{0:} | {0:#X}")]
    fv_length: usize,

    /// Declares capabilities and power-on defaults for the firmware volume.
    #[brw(magic = b"_FVH")]
    #[getset(get_copy = "pub")]
    attr: FvAttr,

    /// Length in bytes of the complete firmware volume header.
    #[br(map = |v: u16| v as usize)]
    #[bw(map = |v: &usize| *v as u16)]
    #[getset(get_copy = "pub")]
    #[debug(format = "{0:} | {0:#X}")]
    header_length: usize,

    /// A 16-bit checksum of the firmware volume header. A valid header sums to zero.
    #[debug(format = "{0:} | {0:#X}")]
    checksum: u16,

    /// Offset, relative to the start of the header, of the extended header
    /// (EFI_FIRMWARE_VOLUME_EXT_HEADER) or zero if there is no extended header.
    #[br(map = |v: u16| v as usize)]
    #[bw(map = |v: &usize| *v as u16)]
    #[getset(get_copy = "pub")]
    #[debug(format = "{0:} | {0:#X}")]
    ext_hdr_offset: usize,
    // Do not use padding macro, because it will skip the read operation
    // Which will cause checksum fail.
    _reserved: u8,

    /// Set to 2. Future versions of this specification may define new header fields and will
    /// increment the Revision field accordingly.
    #[getset(get_copy = "pub")]
    revision: u8,

    /// An array of run-length encoded FvBlockMapEntry structures. The array is
    /// terminated with an entry of {0,0}.
    #[br(count = (header_length - 0x32) / 8)]
    block_map: Vec<BlockMap>,
}

impl FvHdr {
    pub const EFI_FIRMWARE_FILE_SYSTEM2_GUID: Uuid =
        uuid::uuid!("8C8CE578-8A3D-4f1c-9935-896185C32DD3");
    pub const EFI_FIRMWARE_FILE_SYSTEM3_GUID: Uuid =
        uuid::uuid!("5473C07A-3DCB-4dca-BD6F-1E9689E7349A");
    pub const ZERO_VECTOR: [u8; 16] = [0; 16];
    pub const FV_HEADER_SIGNATURE: u32 = 0x4856465F; // "_FVH"
    pub const PEI_APRIORI_FILE_NAME_GUID: Uuid =
        uuid::uuid!("1B45CC0A-156A-428A-AF62-49864DA0E6E6");
    pub const EFI_APRIORI_GUID: Uuid = uuid::uuid!("FC510EE7-FFDC-11D4-BD41-0080C73C8881");
    pub const CHECKSUM_OFFSET: usize = 50;
}

#[binrw]
#[brw(little)]
#[derive(Clone, Copy)]
pub struct FvAttr {
    data: u32,
}

impl FvAttr {
    pub const EFI_FVB2_READ_DISABLED_CAP: u32 = 0x00000001;
    pub const EFI_FVB2_READ_ENABLED_CAP: u32 = 0x00000002;
    pub const EFI_FVB2_READ_STATUS: u32 = 0x00000004;
    pub const EFI_FVB2_WRITE_DISABLED_CAP: u32 = 0x00000008;
    pub const EFI_FVB2_WRITE_ENABLED_CAP: u32 = 0x00000010;
    pub const EFI_FVB2_WRITE_STATUS: u32 = 0x00000020;
    pub const EFI_FVB2_LOCK_CAP: u32 = 0x00000040;
    pub const EFI_FVB2_LOCK_STATUS: u32 = 0x00000080;
    pub const EFI_FVB2_STICKY_WRITE: u32 = 0x00000200;
    pub const EFI_FVB2_MEMORY_MAPPED: u32 = 0x00000400;
    pub const EFI_FVB2_ERASE_POLARITY: u32 = 0x00000800;
    pub const EFI_FVB2_READ_LOCK_CAP: u32 = 0x00001000;
    pub const EFI_FVB2_READ_LOCK_STATUS: u32 = 0x00002000;
    pub const EFI_FVB2_WRITE_LOCK_CAP: u32 = 0x00004000;
    pub const EFI_FVB2_WRITE_LOCK_STATUS: u32 = 0x00008000;
    pub const EFI_FVB2_ALIGNMENT: u32 = 0x001F0000;
    pub const EFI_FVB2_WEAK_ALIGNMENT: u32 = 0x80000000;

    pub fn raw(&self) -> u32 {
        self.data
    }
    pub fn read_disable_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_READ_DISABLED_CAP != 0
    }
    pub fn read_enable_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_READ_ENABLED_CAP != 0
    }
    pub fn read_status(&self) -> bool {
        self.raw() & Self::EFI_FVB2_READ_STATUS != 0
    }
    pub fn write_disable_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_WRITE_DISABLED_CAP != 0
    }
    pub fn write_enable_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_WRITE_ENABLED_CAP != 0
    }
    pub fn write_status(&self) -> bool {
        self.raw() & Self::EFI_FVB2_WRITE_STATUS != 0
    }
    pub fn lock_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_LOCK_CAP != 0
    }
    pub fn lock_status(&self) -> bool {
        self.raw() & Self::EFI_FVB2_LOCK_STATUS != 0
    }
    pub fn sticky_write(&self) -> bool {
        self.raw() & Self::EFI_FVB2_STICKY_WRITE != 0
    }
    pub fn memory_mapped(&self) -> bool {
        self.raw() & Self::EFI_FVB2_MEMORY_MAPPED != 0
    }
    pub fn erase_polarity(&self) -> u8 {
        if self.raw() & Self::EFI_FVB2_ERASE_POLARITY != 0 {
            1
        } else {
            0
        }
    }
    pub fn read_lock_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_READ_LOCK_CAP != 0
    }
    pub fn read_lock_status(&self) -> bool {
        self.raw() & Self::EFI_FVB2_READ_LOCK_STATUS != 0
    }
    pub fn write_lock_cap(&self) -> bool {
        self.raw() & Self::EFI_FVB2_WRITE_LOCK_CAP != 0
    }
    pub fn write_lock_status(&self) -> bool {
        self.raw() & Self::EFI_FVB2_WRITE_LOCK_STATUS != 0
    }
    pub fn alignment(&self) -> u32 {
        let power = (self.raw() & Self::EFI_FVB2_ALIGNMENT) >> 16;
        2 << power
    }
    pub fn weak_alignment(&self) -> bool {
        self.raw() & Self::EFI_FVB2_WEAK_ALIGNMENT != 0
    }
}

impl Debug for FvAttr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0} | {0:#X} | ", self.raw())?;
        if self.read_disable_cap() {
            write!(f, "READ_DISABLE_CAP ")?;
        }
        if self.read_enable_cap() {
            write!(f, "READ_ENABLE_CAP ")?;
        }
        if self.read_status() {
            write!(f, "READ_STATUS ")?;
        }
        if self.write_disable_cap() {
            write!(f, "WRITE_DISABLE_CAP ")?;
        }
        if self.write_enable_cap() {
            write!(f, "WRITE_ENABLE_CAP ")?;
        }
        if self.write_status() {
            write!(f, "WRITE_STATUS ")?;
        }
        if self.lock_cap() {
            write!(f, "LOCK_CAP ")?;
        }
        if self.lock_cap() {
            write!(f, "LOCK_STATUS ")?;
        }
        if self.sticky_write() {
            write!(f, "STICKY_WRITE ")?;
        }
        if self.memory_mapped() {
            write!(f, "MEMORY_MAPPED ")?;
        }
        if self.read_lock_cap() {
            write!(f, "READ_LOCK_CAP ")?;
        }
        if self.read_lock_status() {
            write!(f, "READ_LOCK_STATUS ")?;
        }
        if self.write_lock_cap() {
            write!(f, "WRITE_LOCK_CAP ")?;
        }
        if self.write_lock_status() {
            write!(f, "WRITE_LOCK_STATUS ")?;
        }
        if self.weak_alignment() {
            write!(f, "WEAK_ALIGNMENT ")?;
        }
        write!(f, "ERASE_POLARITY({}) ", self.erase_polarity())?;
        write!(f, "ALIGNMENT({:#X})", self.alignment())
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, CopyGetters)]
pub struct BlockMap {
    #[br(map = |v: u32| v as usize)]
    #[bw(map = |v: &usize| *v as u32)]
    #[getset(get_copy = "pub")]
    num_blocks: usize,
    #[br(map = |v: u32| v as usize)]
    #[bw(map = |v: &usize| *v as u32)]
    #[getset(get_copy = "pub")]
    len: usize,
}

/// Extension header pointed by ExtHeaderOffset of volume header
#[binrw]
#[brw(little)]
#[derive(Clone, custom_debug::Debug, Getters)]
pub struct FvExtHdr {
    /// Firmware volume name.
    #[getset(get = "pub")]
    fv_name: UuidBytes,

    /// Size of the rest of the extension header, including this structure.
    #[br(map = |v: u32| v as usize)]
    #[bw(map = |v: &usize| *v as u32)]
    #[debug(format = "{0:} | {0:#X}")]
    ext_hdr_size: usize,
    #[br(parse_with=read_remaining_length, args(ext_hdr_size - 20, ()))]
    #[getset(get = "pub")]
    entries: Vec<FvExtEntry>,
}

/// Entry struture for describing FV extension header
#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
pub struct FvExtEntry {
    /// Size of this header extension.
    #[br(map = |v: u16| v as usize)]
    #[bw(map = |v: &usize| *v as u16)]
    size: usize,

    /// Type of the header.
    entry_type: u16,
    #[br(args(entry_type, size - 4))]
    payload: FvExtEntryPayload,
}

#[binrw]
#[brw(little)]
#[br(import(entry_type: u16, length:usize) )]
#[derive(Debug, Clone)]
pub enum FvExtEntryPayload {
    /// This extension header provides a mapping between a GUID and an OEM file type.
    #[br(pre_assert(entry_type == 0x01))]
    OemType(#[br(args(length))] FvExtEntryOemType),

    /// This extension header EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE provides a vendor specific
    /// GUID FormatType type which includes a length and a successive series of data bytes.
    #[br(pre_assert(entry_type == 0x02))]
    GuidType(#[br(args(length))] FvExtEntryGuidType),

    /// The EFI_FIRMWARE_VOLUME_EXT_ENTRY_USED_SIZE_TYPE can be used to find
    /// out how many EFI_FVB2_ERASE_POLARITY bytes are at the end of the FV.
    #[br(pre_assert(entry_type == 0x03))]
    UsedSizeType(FvExtEntryUsedSizeType),
}

/// This extension header provides a mapping between a GUID and an OEM file type.
#[binrw]
#[brw(little)]
#[br(import(length:usize) )]
#[derive(Debug, Clone, Getters, CopyGetters)]
pub struct FvExtEntryOemType {
    /// A bit mask, one bit for each file type between 0xC0 (bit 0) and 0xDF (bit 31). If a bit
    /// is '1', then the GUID entry exists in Types. If a bit is '0' then no GUID entry exists in Types.
    #[getset(get_copy = "pub")]
    type_mask: u32,

    /// An array of GUIDs, each GUID representing an OEM file type.
    #[br(count = (length - 4) / 16)]
    #[getset(get = "pub")]
    types: Vec<UuidBytes>,
}

/// This extension header EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE provides a vendor specific
/// GUID FormatType type which includes a length and a successive series of data bytes.
#[binrw]
#[brw(little)]
#[br(import(length:usize) )]
#[derive(custom_debug::Debug, Clone, Getters)]
pub struct FvExtEntryGuidType {
    /// Vendor-specific GUID.
    #[getset(get = "pub")]
    format_type: UuidBytes,

    /// An arry of bytes of length Length.
    #[br(count = length - 16)]
    #[getset(get = "pub")]
    #[debug(with = "buf_fmt")]
    data: Vec<u8>,
}

/// The EFI_FIRMWARE_VOLUME_EXT_ENTRY_USED_SIZE_TYPE can be used to find
/// out how many EFI_FVB2_ERASE_POLARITY bytes are at the end of the FV.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, CopyGetters)]
pub struct FvExtEntryUsedSizeType {
    /// The number of bytes of the FV that are in uses. The remaining
    /// EFI_FIRMWARE_VOLUME_HEADER FvLength minus UsedSize bytes in
    /// the FV must contain the value implied by EFI_FVB2_ERASE_POLARITY.
    #[getset(get_copy = "pub")]
    used_size: u32,
}

#[cfg(test)]
mod test {
    use crate::FindFvIter;
    use anyhow::Result as AnyResult;
    #[test]
    fn test_fv() -> AnyResult<()> {
        for fv in FindFvIter::new(std::fs::read("test/OVMF.fd")?.as_slice()) {
            dbg!(fv);
        }

        Ok(())
    }
}
