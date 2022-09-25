import socket
import os
import sys

from .message import DBusMessage

ORG_FREEDESKTOP_DBUS = {'path': '/org/freedesktop/DBus',
                        'destination': 'org.freedesktop.DBus'}

def dbus_socket_path(uri:str) -> str:
    """ extract unix socket path from the dbus uri """
    for address in uri.split(';'):
        transport, arguments = address.split(':', 1)
        if transport == 'unix':
            args = dict(kv.split('=', 1) for kv in arguments.split(','))
            if 'abstract' in args:
                return '\0' + args['abstract']
            elif 'path' in args and os.path.exists(args['path']):
                return args['path']
    return None

def dbus_user_path() -> str:
    default = 'unix:path={:s}/bus'.format(os.environ['XDG_RUNTIME_DIR']) \
                  if 'XDG_RUNTIME_DIR' in os.environ else \
                      'unix:path=/run/user/{0:d}/bus' \
                      ';unix:path=/var/run/user/{0:d}/bus'.format(os.getuid())
    return dbus_socket_path(os.environ.get('DBUS_SESSION_BUS_ADDRESS',
                                           default))

def dbus_system_path() -> str:
    default = 'unix:path=/run/dbus/system_bus_socket' \
              ';unix:path=/var/run/dbus/system_bus_socket'
    return dbus_socket_path(os.environ.get('DBUS_SYSTEM_BUS_ADDRESS',
                                           default))

class DBusError(Exception): pass

class DBus:
    def __init__(self, user:bool=False, raise_on_error:bool=False):
        self.path = dbus_user_path() if user else dbus_system_path()
        self.raise_on_error = raise_on_error
        self._serial = self._name = self._socket = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exception):
        self.disconnect()

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.setblocking(True)
        s.connect(self.path)
        s.sendall(b'\x00')
        self._socket = s
        self._serial = iter(range(1, 2**32))
        self.auth(data=str(os.geteuid()))
        self.begin()
        self._name = self.hello()

    def disconnect(self):
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        self._socket = None
        self._serial = self._name = None

    @property
    def fileno(self):
        return self._socket.fileno()

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name:str):
        if self.request_name(name, 0b110) not in (1, 4):
            error = 'failed to become primary owner of "%s"' % name
            raise DBusError(error)
        self._name = name

    def auth(self, mechanism:str='EXTERNAL', data:str=''):
        string = ' '.join(s for s in ('AUTH',
                                      mechanism,
                                      data.encode('utf8').hex()) if s)
        self._sendstr(string)
        string = self._recvstr()
        if not string.startswith('OK'):
            raise DBusError(string)

    def begin(self):
        self._sendstr('BEGIN')

    def data(self, data:str=None) -> str:
        self._sendstr('DATA')
        if data:
            self._sendstr(' ' + data.encode('ascii').hex())
        return self._recvstr()

    def error(self) -> str:
        self._sendstr('ERROR')
        reply = self._recvstr()
        if not reply.startswith('REJECTED'):
            raise ValueError('unexpected reply from server: "{}"'.format(reply))
        return reply[9:]

    def negotiate_unix_fd(self) -> str:
        self._sendstr('NEGOTIATE_UNIX_FD')
        reply = self._recvstr()
        if not reply.startswith('AGREE_UNIX_FD'):
            raise ValueError('unexpected reply from server: "{}"'.format(reply))
        return reply[14:]

    def cancel(self) -> str:
        self._sendstr('CANCEL')
        reply = self._recvstr()
        if not reply.startswith('REJECTED'):
            raise ValueError('unexpected reply from server: "{}"'.format(reply))
        return reply[9:]

    def ping(self) -> bool:
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus.Peer',
                        member='Ping')
        return self.call(m).type == 2

    def get_machine_id(self):
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus.Peer',
                        member='GetMachineId')
        return self.call(m).body[0]

    def introspect(self, path:str, destination:str):
        m = DBusMessage(path=path, destination=destination,
                        interface='org.freedesktop.DBus.Introspectable',
                        member='Introspect')
        return self.call(m).body[0]

    def get(self, path:str, interface:str, destination:str,
                  attribute:str):
        m = DBusMessage(interface='org.freedesktop.DBus.Properties',
                        path=path, destination=destination,
                        member='Get', signature='ss')
        m.body = (interface, attribute)
        return self.call(m).body[0][1]

    def set(self, path:str, interface:str, destination:str,
                  attribute:str, signature:str, value:str) -> bool:
        m = DBusMessage(path=path,
                        interface='org.freedesktop.DBus.Properties',
                        destination=destination,
                        member='Set', signature='ssv')
        m.body = (interface, attribute, (signature, value))
        return self.call(m).type == 2

    def get_all(self, path:str, interface:str, destination:str):
        m = DBusMessage(interface='org.freedesktop.DBus.Properties',
                        path=path, destination=destination,
                        member='GetAll', signature='s')
        m.body = (interface, )
        return {k: v[1] for k, v in self.call(m).body[0].items()}

    def become_monitor(self, rules:list=[]) -> bool:
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus.Monitoring',
                        member='BecomeMonitor', signature='asu')
        m.body = (rules, 0)
        self.raise_on_error = False
        return self.call(m).type == 2

    def get_managed_objects(self):
        # interface: 'org.freedesktop.DBus.ObjectManager'
        # member: 'GetManagedObjects'
        raise NotImplementedError

    def hello(self) -> str:
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='Hello')
        return self.call(m).destination

    def request_name(self, name:str, flags:int=0):
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='RequestName', signature='su')
        m.body = (name, flags)
        return self.call(m).body[0]

    def release_name(name:str):
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='ReleaseName', signature='s')
        m.body = (name, )
        return self.call(m)

    def list_queued_owners(name:str):
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='ListQueuedOwners', signature='s')
        m.body = (name, )
        return self.call(m)

    def list_names(self) -> list:
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='ListNames')
        return self.call(m).body[0]

    def list_activatable_names(self) -> list:
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='ListActivatableNames')
        return self.call(m).body[0]

    def name_has_owner(name:str):
        raise NotImplementedError

    def start_service_by_name(name:str, flags:int=0):
        # StartServiceByName | su (name, flags)
        raise NotImplementedError

    def update_activation_environment(self, **environment):
        # UpdateActivationEnvironment | a{ss} (environment, )
        raise NotImplementedError

    def get_name_owner(self, bus_name:str):
        # GetNameOwner | s (name, )
        raise NotImplementedError

    def get_connection_unix_user(self, bus_name:str):
        # GetConnectionUnixUser | s (bus_name, )
        raise NotImplementedError

    def get_connection_unix_process_id(self, bus_name:str):
        # GetConnectionUnixProcessID | s (bus_name, )
        raise NotImplementedError

    def get_connection_credentials(self, bus_name:str):
        # GetConnectionCredentials | s (bus_name, )
        raise NotImplementedError

    def get_adt_audit_session_data(self, bus_name:str):
        # GetAdtAuditSessionData | s (bus_name, )
        raise NotImplementedError

    def get_connection_selinux_security_context(self, bus_name:str):
        # GetAdtAuditSessionData | s (bus_name, )
        raise NotImplementedError

    def add_match(self, **rules) -> bool:
        rule = ','.join('{}={}'.format(k, v) for k, v in rules.items())
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='AddMatch', signature='s')
        m.body = (rule, )
        return self.call(m).type == 2

    def remove_match(self, **rules) -> bool:
        rule = ','.join('{}={}'.format(k, v) for k, v in rules.items())
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus',
                        member='RemoveMatch', signature='s')
        m.body = (rule, )
        return self.call(m).type == 2

    def get_id(self) -> str:
        m = DBusMessage(**ORG_FREEDESKTOP_DBUS,
                        interface='org.freedesktop.DBus.Properties',
                        member='GetId')
        return self.call(m).body

    def call(self, message:bytes=None) -> DBusMessage:
        """ send message and return reply. returns message reply """
        assert message.type == 1 and not message.flags & 0b1
        return self.recv({'reply': self.send(message)})

    def send(self, message:bytes=None) -> int:
        """ send message without waiting for reply. returns serial """
        message.serial = next(self._serial)
        self._sendmsg(message)
        #print("SENT:", message)
        return message.serial

    def recv(self, header:dict={}, body:tuple=()) -> DBusMessage:
        """ receive message matching header and/or body. returns message """
        while True:
            message = self._recvmsg()
            if message.match(header, body):
                #print("RECEIVED:", message, message.body)
                if self.raise_on_error and message.type == 3:
                    error = '%s: %s' % (message.error, ';'.join(message.body))
                    raise DBusError(error)
                return message
            else:
                #print("SKIPPED:", message, message.body)
                continue

    def _sendstr(self, string:str):
        self._socket.sendall('{}\r\n'.format(string).encode('utf8'))

    def _recvstr(self) -> str:
        buffer = bytearray()
        while buffer[-2:] != b'\r\n': buffer.extend(self._socket.recv(1))
        return buffer[:-2].decode('utf8')

    def _sendmsg(self, message:DBusMessage):
        self._socket.sendall(message)

    def _recvmsg(self) -> DBusMessage:
        message, size = bytearray(), 16
        while len(message) < size:
            buffer = self._socket.recv(size-len(message))
            if not buffer:
                raise ConnectionResetError('received zero bytes from dbus-server')
            message.extend(buffer)
            if len(message) == 16:
                message = DBusMessage(message)
                size = sum(message.length)
        return message
