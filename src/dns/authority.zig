const std = @import("std");

pub const Authority = struct {
    /// pointer to QNAME at offset 12 (avoids repeating the name)
    comptime NAME: u16 = 0xC00C,
    /// SOA
    comptime TYPE: u16 = 0x0006,
    /// IN
    comptime CLASS: u16 = 0x0001,
    /// negative-cache TTL
    comptime TTL: u32 = 3600,
    /// length of the RDATA below
    comptime RDLENGTH: u16 = 22,
    /// root label (placeholder primary NS)
    comptime MNAME: u8 = 0x00,
    /// root label (placeholder admin mailbox)
    comptime RNAME: u8 = 0x00,
    comptime SERIAL: u32 = 1,
    comptime REFRESH: u32 = 3600,
    comptime RETRY: u32 = 600,
    comptime EXPIRE: u32 = 86400,
    /// negative-cache TTL - the field that matters, keep == record TTL
    comptime MINIMUM: u32 = 3600,

    /// Wire size of the record: 12-byte RR header + 22-byte RDATA. Fixed at 34
    /// only because NAME is a 2-byte compression pointer and MNAME/RNAME are
    /// root labels; a real MNAME/RNAME would make this variable.
    pub const WIRE_LEN = 34;

    /// Pass in entire DNS packet and write Authority section in DNS packet
    pub fn write_authority_section(
        self: *Authority,
        byte_slice: []u8,
        start_idx: usize,
    ) usize {
        // The 34 bytes below are written unchecked. Today's only caller sizes
        // its buffer exactly, but this is the footgun WIRE_LEN's comment warns
        // about: swap in a real MNAME/RNAME and the record outgrows the space.
        std.debug.assert(byte_slice.len >= start_idx + WIRE_LEN);

        // The owner NAME is a pointer to offset 12, so this record is only
        // valid appended to a message whose QNAME starts there.
        std.debug.assert(start_idx >= 12);

        std.mem.writeInt(u16, byte_slice[start_idx..][0..2], self.NAME, .big);
        std.mem.writeInt(u16, byte_slice[start_idx..][2..4], self.TYPE, .big);
        std.mem.writeInt(u16, byte_slice[start_idx..][4..6], self.CLASS, .big);
        std.mem.writeInt(u32, byte_slice[start_idx..][6..10], self.TTL, .big);
        std.mem.writeInt(u16, byte_slice[start_idx..][10..12], self.RDLENGTH, .big);
        byte_slice[start_idx + 12] = self.MNAME;
        byte_slice[start_idx + 13] = self.RNAME;
        std.mem.writeInt(u32, byte_slice[start_idx..][14..18], self.SERIAL, .big);
        std.mem.writeInt(u32, byte_slice[start_idx..][18..22], self.REFRESH, .big);
        std.mem.writeInt(u32, byte_slice[start_idx..][22..26], self.RETRY, .big);
        std.mem.writeInt(u32, byte_slice[start_idx..][26..30], self.EXPIRE, .big);
        std.mem.writeInt(u32, byte_slice[start_idx..][30..34], self.MINIMUM, .big);

        return start_idx + 34;
    }
};
