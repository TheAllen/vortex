const name_reader = @import("name_reader.zig");

pub const Section = enum {
    answer,
    authority,
    additional,
};

pub const ResourceRecord = struct {
    name: name_reader.Name,
    type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: u32,
    section: Section,
};
