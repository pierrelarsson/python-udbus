import struct
import socket
import os
import sys

from io import BytesIO
from .marshalling import DBusMarshal, DBusUnmarshal, HEADER_FIELDS

ENDIAN = {'little': 108, 'big': 66}

BYTEORDER = {108: 'little', 66: 'big'}

STRUCT_HEADER = {108: struct.Struct('<4B3I'),
                  66: struct.Struct('>4B3I')}

class DBusMessage(bytearray):
    pack = DBusMarshal()
    unpack = DBusUnmarshal()

    def __init__(self, buffer:bytes=None, *,
                       byteorder:str=sys.byteorder, type:int=1,
                       flags:int=0, serial:int=0, **fields):
        if buffer:
            header = STRUCT_HEADER[buffer[0]].unpack(buffer[:16])
        else:
            endian = ENDIAN[byteorder]
            fields = self.pack.fields(byteorder, **fields)
            header = (endian, type, flags, 1, 0, serial, len(fields))
            buffer = STRUCT_HEADER[endian].pack(*header) + fields + b'\0' * 8
        self.__dict__.update({
            'byteorder': BYTEORDER[header[0]],
            'type': header[1],
            'flags': header[2],
            'version': header[3],
            'serial': header[5],
            'length': (16, header[6], -header[6]%8, header[4])})
        super().__init__(buffer[:sum(self.length)])

    def __iadd__(self, value):
        m = "unsupported operand type(s) for +=: '%s' and '%s'"
        raise TypeError(m % (self.__class__.__name__, type(value).__name__))

    def __imul__(self, value):
        m = "unsupported operand type(s) for *=: '%s' and '%s'"
        raise TypeError(m % (self.__class__.__name__, type(value).__name__))

    def __str__(self):
        attrs = ['%s=%s' % (k, repr(v)) for k, v in self.header.items()]
        attrs.append('body={}'.format(bool(self.length[3])))
        return '{}({})'.format(self.__class__.__name__, ', '.join(attrs))

    def __getattr__(self, attr):
        if attr in HEADER_FIELDS:
            p = slice(16, sum(self.length[:2]))
            self.__dict__.update(self.unpack.fields(self.byteorder, self[p]))
            return self.__dict__[attr]
        m = "'%s' has no attribute '%s'"
        raise AttributeError(m % (self.__class__.__name__, attr))

    def __setattr__(self, attr, value):
        if attr == 'type':
            self.__dict__['type'] = value
            super().__setitem__(1, value)
        elif attr == 'flags':
            self.__dict__['flags'] = value
            super().__setitem__(2, value)
        elif attr == 'serial':
            self.__dict__['serial'] = value
            super().__setitem__(slice(8, 12),
                                value.to_bytes(4, self.byteorder))
        elif attr == 'body':
            p = sum(self.length[:3])
            del(self[p:])
            self.extend(self.pack(self.byteorder, self.signature, *value))
            l = len(self)-p
            self.__dict__['length'] = self.length[:3] + (l, )
            super().__setitem__(slice(4, 8), l.to_bytes(4, self.byteorder))
        else:
            m = "attribute '%s' of '%s' objects is not writable"
            raise AttributeError(m % (attr, self.__class__.__name__))

    def __setitem__(self, key, value):
        m = "'%s' object does not support item assignment"
        raise TypeError(m % self.__class__.__name__)

    @property
    def header(self) -> dict:
        return {attr:self.__dict__[attr]
                for attr in ['type', 'flags', 'serial'] + HEADER_FIELDS
                if getattr(self, attr) is not None}

    @property
    def body(self) -> tuple:
        if not self.length[3]: return None
        return tuple(self.unpack(self.byteorder,
                                 self.signature,
                                 self[sum(self.length[:3]):]))

    def match(self, header:dict={}, body:tuple=()) -> bool:
        if self.header.items() >= header.items():
            if not body: return True
            iterator = iter(self.body)
            for v2 in body:
                v1 = next(iterator, None)
                if v2 is not None and v2 != v1:
                    return False
            return True
        return False
