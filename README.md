# WORK IN PROGRESS

µDBUS implementation for/in Python

```
from udbus import DBus, DBusMessage

with DBus(user=True) as dbus:
    for name in dbus.list_names():
        print(name)
```
