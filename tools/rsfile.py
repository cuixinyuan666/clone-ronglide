import struct
import sys

TYPE_NAMES = {
    1: 'u8',
    2: 'u8',
    3: 'i16',
    4: 'u16',
    5: 'i32',
    6: 'u32',
    7: 'f32',
    8: 'f64',
    9: 'u32',
    10: 'f32',
    11: 'f64',
    12: 'date',
    13: 'time',
    14: 'bytes',
    15: 'str',
}


class Field(object):
    def __init__(self, fid, ftype, off, size):
        self.id = fid
        self.type = ftype
        self.off = off
        self.size = size

    def __repr__(self):
        return 'Field(id=%d type=%d off=%d size=%d)' % (self.id, self.type, self.off, self.size)


class RsFile(object):
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        d = self.data
        head_size, = struct.unpack_from('<H', d, 0)
        self.rec_count, = struct.unpack_from('<I', d, 6)
        self.rec_size, = struct.unpack_from('<H', d, 10)
        self.field_count, = struct.unpack_from('<H', d, 12)
        self.fields = []
        p = 14
        for _ in range(self.field_count):
            fid, ftype, off, reserved, size = struct.unpack_from('<HBBBB', d, p)
            self.fields.append(Field(fid, ftype, off, size))
            p += 6
        self.rec_off = head_size
        expected = self.rec_off + self.rec_count * self.rec_size
        self.size_ok = (expected == len(d))

    def record(self, i):
        return self.data[self.rec_off + i * self.rec_size: self.rec_off + (i + 1) * self.rec_size]

    def raw(self, i, field):
        if isinstance(field, int):
            field = self.fields[field]
        return self.record(i)[field.off:field.off + field.size]

    def value(self, i, field):
        if isinstance(field, int):
            field = self.fields[field]
        b = self.raw(i, field)
        if field.type == 15:
            return b.rstrip(b'\x00').decode('gbk', errors='replace')
        if field.type == 14:
            return b
        if field.size == 1:
            return b[0]
        if field.size == 2:
            return struct.unpack('<H', b)[0]
        if field.size == 4:
            if field.type == 10:
                return struct.unpack('<f', b)[0]
            return struct.unpack('<I', b)[0]
        if field.size == 8:
            if field.type == 11:
                return struct.unpack('<d', b)[0]
            return struct.unpack('<Q', b)[0]
        return b

    def dump(self, n=10):
        print('path rec_count=%d rec_size=%d fields=%d head_ok=%s' % (
            self.rec_count, self.rec_size, self.field_count, self.size_ok))
        for f in self.fields:
            print('  ', f)
        for i in range(min(n, self.rec_count)):
            vals = [self.value(i, f) for f in self.fields]
            print(i, vals)


if __name__ == '__main__':
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    RsFile(path).dump(n)
