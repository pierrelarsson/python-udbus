import struct
from io import BytesIO

HEADER_FIELDS = ['path', 'interface', 'member', 'error', 'reply',
                 'destination', 'sender', 'signature', 'unixfds']

HEADER_FIELDS_SIGNATURE = b'\0osssussgu'

class DBusMarshal:
    def __init__(self):
        self.SIGNATURES = {
            121: self.byte,
             97: self.array,              118: self.variant,
             40: self.struct,             123: self.dictentry,
             98: self.boolean,            100: self.double, 
            110: self.integer(2, True),   113: self.integer(2, False),
            105: self.integer(4, True),   117: self.integer(4, False),
            120: self.integer(8, True),   116: self.integer(8, False),
            115: self.string(4, 'utf8'),  111: self.string(4, 'ascii'),
            103: self.string(1, 'ascii'), 104: self.integer(4, False),
        }

    def __call__(self, byteorder:str, signature:str, *data) -> bytes:
        self.byteorder = byteorder
        self.signature = bytearray(signature[::-1], 'ascii')
        b = BytesIO()
        self.write, self.tell, self.seek = b.write, b.tell, b.seek
        for item in data:
            self.SIGNATURES[self.signature.pop()](item)
        return b.getvalue()

    @classmethod
    def fields(cls, byteorder:str, **fields) -> bytearray:
        buffer = bytearray()
        for i, signature, value in [(i, HEADER_FIELDS_SIGNATURE[i], fields.get(l))
                                    for i, l in enumerate(HEADER_FIELDS, 1)]:
            if value is None: continue
            b = b'%c\1%c\0' % (i, signature)
            buffer.extend(b.rjust(-len(buffer)%8 + 4, b'\0'))
            if signature == 117:
                buffer.extend(value.to_bytes(4, byteorder))
            else:
                b = value.encode('utf8')
                l = len(b).to_bytes(1 if signature == 103 else 4, byteorder)
                buffer.extend(l + b + b'\0')
        return buffer

    def align(self, alignment:int):
        self.write(b'\0' * (-self.tell()%alignment))

    def byte(self, byte:int):
        self.write(b'%c' % byte)

    def boolean(self, boolean:bool):
        f = b'%c\0\0\0' if self.byteorder == 'little' else b'\0\0\0%c'
        self.align(4)
        self.write(f % int(boolean))

    def integer(self, size:int, signed:bool):
        def _integer(integer:int):
            self.align(size)
            self.write(integer.to_bytes(size, self.byteorder, signed=signed))
        return _integer

    def double(self, double:float):
        f = '<d' if self.byteorder == 'little' else '>d'
        self.align(8)
        self.write(struct.pack(f, double))

    def string(self, size:int, encoding:str):
        def _string(string:str):
            b = string.encode(encoding)
            if size > 1: self.align(size)
            self.write(len(b).to_bytes(size, self.byteorder))
            self.write(b)
            self.write(b'\0')
        return _string

    def array(self, l:list):
        marshaller = self.SIGNATURES[self.signature.pop()]
        self.align(4)
        self.write(b'####')
        start = self.tell()
        reset = self.signature
        for item in l:
            self.signature = reset.copy()
            marshaller(item)
        length = self.tell()-start
        self.seek(start-4, 0)
        self.write(length.to_bytes(4, self.byteorder))
        self.seek(0, 2)

    def struct(self, t:tuple):
        self.align(8)
        item = iter(t)
        while self.signature:
            s = self.signature.pop()
            if s == 41: break
            self.SIGNATURES[s](next(item))

    def variant(self, t:tuple):
        self.SIGNATURES[103](t[0])
        reset, self.signature = self.signature, bytearray(t[0][::-1], 'ascii')
        self.SIGNATURES[self.signature.pop()](t[1])
        self.signature = reset

    def dictentry(self, d:dict):
        self.align(8)
        k, v = d.popitem()
        key = self.SIGNATURES[self.signature.pop()](k)
        value = self.SIGNATURES[self.signature.pop()](v)
        assert self.signature.pop() == 125

class DBusUnmarshal:
    def __init__(self):
        self.SIGNATURES = {
            121: self.byte,
             97: self.array,              118: self.variant,
             40: self.struct,             123: self.dictentry,
             98: self.boolean,            100: self.double, 
            110: self.integer(2, True),   113: self.integer(2, False),
            105: self.integer(4, True),   117: self.integer(4, False),
            120: self.integer(8, True),   116: self.integer(8, False),
            115: self.string(4, 'utf8'),  111: self.string(4, 'ascii'),
            103: self.string(1, 'ascii'), 104: self.integer(4, False),
        }

    def __call__(self, byteorder:str, signature:str, data:bytes) -> list:
        self.byteorder = byteorder
        self.signature = bytearray(signature[::-1], 'ascii')
        b = BytesIO(data)
        self.read, self.tell, self.seek = b.read, b.tell, b.seek
        l = []
        while self.signature:
            l.append(self.SIGNATURES[self.signature.pop()]())
        return l

    @classmethod
    def fields(cls, byteorder:str, buffer:bytes) -> dict:
        p, end, fields = 0, len(buffer), dict.fromkeys(HEADER_FIELDS)
        while p < end:
            i, signature, p = (buffer[p], buffer[p+2], p+4)
            value, p = (buffer[p], p+1) if signature == 103 else \
                       (int.from_bytes(buffer[p:p+4], byteorder), p+4)
            if signature != 117:
                value, p = buffer[p:p+value].decode('utf8'), p+value+1
            p += -p%8
            fields[HEADER_FIELDS[i-1]] = value
        return fields

    def align(self, alignment:int):
        self.seek(-self.tell()%alignment, 1)

    def byte(self) -> int:
        return self.read(1)[0]

    def boolean(self) -> bool:
        self.align(4)
        return self.read(4) != b'\0\0\0\0'

    def integer(self, size:int, signed:bool):
        def _integer() -> int:
            self.align(size)
            return int.from_bytes(self.read(size),
                                  self.byteorder,
                                  signed=signed)
        return _integer

    def double(self) -> float:
        f = '<d' if self.byteorder == 'little' else '>d'
        self.align(8)
        return struct.unpack(f, self.read(8))

    def string(self, size:int, encoding:str):
        def _string() -> str:
            if size > 1: self.align(size)
            b = self.read(int.from_bytes(self.read(size), self.byteorder))
            self.seek(1, 1)
            return b.decode(encoding)
        return _string

    def array(self) -> list:
        s = self.signature.pop()
        container = {} if s == 123 else []
        unmarshaller = self.SIGNATURES[s]
        end = self.SIGNATURES[117]() + self.tell()
        reset = self.signature
        add = container.update if s == 123 else container.append
        while self.tell() < end:
            self.signature = reset.copy()
            add(unmarshaller())
        return container

    def struct(self) -> tuple:
        self.align(8)
        array = []
        while self.signature:
            s = self.signature.pop()
            if s == 41: break
            array.append(self.SIGNATURES[s]())
        return tuple(array)

    def variant(self) -> tuple:
        signature = self.SIGNATURES[103]()
        reset, self.signature = self.signature, bytearray(signature[::-1], 'ascii')
        t = (signature, self.SIGNATURES[self.signature.pop()]())
        self.signature = reset
        return t
        
    def dictentry(self):
        self.align(8)
        key = self.SIGNATURES[self.signature.pop()]()
        value = self.SIGNATURES[self.signature.pop()]()
        assert self.signature.pop() == 125
        return {key: value}
