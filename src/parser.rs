extern crate nom;

use nom::{IResult, le_u64, le_u32, le_u16, le_u8, rest};
use std::cmp::Ordering;

//
// PFS file header
//
#[derive(Debug, PartialEq, Eq)]
pub struct PfsHeader {
    pub header_version : u32,
    pub data_size : u32,
}

pub fn pfs_header(input : &[u8]) -> IResult<&[u8], PfsHeader> {
    do_parse!( input,
        tag!(b"PFS.HDR.") >>
        v: le_u32 >>
        s: le_u32 >>
        ( PfsHeader {
            header_version: v,
            data_size: s,
            }
        )
    )
}

//
// PFS file footer
//
#[derive(Debug, PartialEq, Eq)]
pub struct PfsFooter {
    pub checksum : u32,
    pub data_size : u32,
}

pub fn pfs_footer(input : &[u8]) -> IResult<&[u8], PfsFooter> {
    do_parse!(input,
    s : le_u32 >> 
    c : le_u32 >>
    tag!(b"PFS.FTR.") >>
        ( PfsFooter {
            checksum: c,
            data_size: s,
            }
        )
    )
}

//
// GUID
//
#[derive(Debug, PartialEq, Eq)]
pub struct Guid {
    pub data1 : u32,
    pub data2 : u16,
    pub data3 : u16,
    pub data4 : [u8; 8],
}

pub fn guid (input : &[u8]) -> IResult<&[u8], Guid> {
    do_parse!(input,
        d1 : le_u32 >>
        d2 : le_u16 >>
        d3 : le_u16 >>
        d4 : count_fixed!(u8, le_u8, 8) >>
        ( Guid {
                data1 : d1,
                data2 : d2,
                data3 : d3,
                data4 : d4,
            }
        )
    )
}

//
// PFS section
//
#[derive(Debug, PartialEq, Eq)]
pub struct PfsSection<'a> {
    pub name : String,
    pub guid : Guid,
    pub header_version: u32,
    pub version_type : [u8; 4],
    pub version : [u16; 4],
    pub reserved : u64,
    pub data_size : u32,
    pub data_sig_size : u32,
    pub meta_size : u32,
    pub meta_sig_size : u32,
    pub unknown : [u8; 16],
    pub data : Option<&'a[u8]>,
    pub data_sig : Option<&'a[u8]>,
    pub meta : Option<&'a[u8]>,
    pub meta_sig : Option<&'a[u8]>,
}

pub fn pfs_section (input : &[u8]) -> IResult<&[u8], PfsSection> {
    do_parse!(input,
        g   : guid >>
        hv  : le_u32 >>
        vt  : count_fixed!(u8, le_u8, 4) >>
        v   : count_fixed!(u16, le_u16, 4) >>
        r   : le_u64 >>
        ds  : le_u32 >>
        dss : le_u32 >>
        ms  : le_u32 >>
        mss : le_u32 >> 
        u   : count_fixed!(u8, le_u8, 16) >>
        dp  : cond_with_error!(ds > 0, take!(ds)) >> 
        dsp : cond_with_error!(dss > 0, take!(dss)) >> 
        mp  : cond_with_error!(ms > 0, take!(ms)) >> 
        msp : cond_with_error!(mss > 0, take!(mss)) >>
        ( PfsSection {
                name : String::new(), // Name will be populated later based on information section
                guid : g,
                header_version : hv,
                version_type : vt,
                version : v,
                reserved : r,
                data_size : ds,
                data_sig_size : dss,
                meta_size : ms,
                meta_sig_size : mss,
                unknown : u,
                data : dp,
                data_sig: dsp,
                meta : mp,
                meta_sig: msp,
            }
        )
    )
}


//
// Complete PFS file 
//
#[derive(Debug, PartialEq, Eq)]
pub struct PfsFile<'a> {
    pub header :  PfsHeader,
    pub sections : Vec<PfsSection<'a> >,
    pub footer :  PfsFooter,
}

pub fn pfs_file (input : &[u8]) -> IResult<&[u8], PfsFile> {
    do_parse!(input,
        h  : pfs_header >>
        sf : many_till!(pfs_section, pfs_footer) >>
        ( PfsFile {
                header: h,
                sections: sf.0,
                footer: sf.1,
            }
        )
    )
}


//
// PFS zlib-compressed section
//
#[derive(Debug, PartialEq, Eq)]
pub struct PfsCompressedSection<'a> {
    pub size : u32,
    pub data : &'a[u8],
}

pub fn pfs_compressed_section (input : &[u8]) -> IResult<&[u8], PfsCompressedSection> {
    do_parse!(input,
        s : le_u32 >>   // Obtain data size
        tag!(b"\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51") >> // Check for compressed section header
        take!(1) >>     // Skip 1 byte
        d : take!(s) >> // Obtain payload
        take!(16) >>    // Skip footer
        ( PfsCompressedSection {
                size: s,
                data: d,
            }
        )
    )
}

//
// PFS chunk 
//
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PfsChunk<'a> {
    pub order_number : u16,
    pub data : &'a[u8],
}

impl<'a> Ord for PfsChunk<'a> {
    fn cmp(&self, other: &PfsChunk<'a>) -> Ordering {
        self.order_number.cmp(&other.order_number)
    }
}

impl<'a> PartialOrd for PfsChunk<'a> {
    fn partial_cmp(&self, other: &PfsChunk<'a>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn pfs_chunk (input : &[u8]) -> IResult<&[u8], PfsChunk> {
    do_parse!(input,
        take!(0x3E) >> // Skip first 0x3E bytes
        on : le_u16 >> // Get order number
        take!(0x248 - 0x40) >> // Skip the rest of chunk header
        d: rest >>
        ( PfsChunk {
                order_number: on,
                data : d,
            }
        )
    )
}

//
// PFS information section 
//
#[derive(Debug, PartialEq, Eq)]
pub struct PfsInfoSection {
    pub header_version : u32,
    pub guid : Guid,
    pub version : [u16; 4],
    pub version_type : [u8; 4],
    pub name : String,
}

pub fn pfs_info_section (input : &[u8]) -> IResult<&[u8], PfsInfoSection> {
    do_parse!(input,
        hv : le_u32 >>
        g  : guid >> 
        v  : count_fixed!(u16, le_u16, 4) >>
        vt : count_fixed!(u8, le_u8, 4) >>
        l  : le_u16 >> 
        n  : count!(le_u16, l as usize) >>
             tag!("\x00\x00") >>
        ( PfsInfoSection {
                header_version: hv,
                guid : g,
                version : v,
                version_type : vt,
                name : String::from_utf16_lossy(&n),
            }
        )
    )
}

pub fn pfs_info (input : &[u8]) -> IResult<&[u8], Vec<PfsInfoSection>> {
    do_parse!(input,
        v : many0!(complete!(pfs_info_section)) >> 
        ( v )
    )
}