#!/usr/bin/python

# The MIT License
#
# Copyright (c) 2012 Radu Cristescu
#
# Adapted to Python 3 by Thomas Meyer in 2022
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import struct
import socket
import sys
import os
import stat
from time import localtime, strftime
import shlex

#DEFAULT_HOST = "vexed4.alioth.net"
#DEFAULT_HOST = "fujinet.online"
DEFAULT_HOST = "fujinet.krion.io"
# V1.0 server
#DEFAULT_HOST = "nihirash.net"

# Timeout in seconds
DEFAULT_TIMEOUT = 15
# Maximum number of bytes to show in dump command
DUMP_MAX_BYTES = 0xffff

def printHelp():
    print("Commands:")
    print("  ls [-l] [-x] [<path>]                       List contents of remote directory")
    print("  dir [-l] [-x] [<path>]                      Same as 'ls'")
    print("  l [<path>]                                  Short for ls -l")
    print("  lx [<path>]                                 Short for ls -lx")
    print("  cd <path>                                   Change remote directory")
    print("  lcd <path>                                  Change local directory")
    print("  pwd                                         Show current remote directory")
    print("  cat <remote filename>                       Download and print a file")
    print("  dump <remote filename>                      Download and print a file as hex")
    print("  rm <remote filename>                        Remove a file")
    print("  get <remote filename> [<local filename>]    Download a file")
    print("  put <local filename> [<remote filename>]    Upload a file")
    print("  mkdir <path>                                Create directory")
    print("  rmdir <path>                                Remove directory")
    print("  ?,h,help                                    This help")

class DirEntry:
    def __init__(self):
        self.flags = 0
        self.size = 0
        self.ctime = 0
        self.mtime = 0
        self.name = ""

    def setFlags(self, flags):
        self.flags = flags
        return self

    def setSize(self, size):
        self.size = size
        return self

    def setCtime(self, ctime):
        self.ctime = localtime(ctime)
        return self

    def setMtime(self, mtime):
        self.mtime = localtime(mtime)
        return self

    def setName(self, name):
        self.name = name
        return self

    def getData(self):
        return self.flags, self.size, self.ctime, self.mtime, self.name

# Dump byte array in 16 hex columns plus ASCII representation
def dumpHex(barray, maxBytes = 65535):
    res = ""
    hexout = ""
    litout = ""

    i = 0
    offs = 0
    for b in barray:
        hexout += f"{b:02x} "
        litout += chr(b) if b >= 32 else '.'

        if i >= 15:
            res += f"{offs:04x}: {hexout}   {litout}\n"
            i = 0
            offs += 16
            hexout = ""
            litout = ""
            if offs > maxBytes:
                break
        else:
            i += 1
    if i > 0:
        res += f"{offs:04x}: {hexout:<51}{litout}"
    return res

# Get a null-terminated string from bytes.
def getCstr(data, pos):
    end = data.find(b"\0", pos)
    if end == -1:
        return None, None
    string = data[pos:end].decode("utf-8")
    return string, end + 1

def fullPath(cwd, path):
    # TODO Use pathlib?
    result = os.path.normpath(f"{cwd}/{path}").replace("\\", "/") if path[0] != "/" else path

    ## http://stackoverflow.com/questions/7816818/why-doesnt-os-normapath-collapse-a-leading-double-slash
    ## It doesn't hurt having a double slash, but it looks ugly and inconsistent, so we clean it up
    if result[:2] == "//":
        result = result[1:]

    return result

# From tnfsd/directory.h
class tnfs_diropt:
    NO_FOLDERSFIRST = 0x01
    NO_SKIPHIDDEN = 0x02
    NO_SKIPSPECIAL = 0x04
    DIR_PATTERN = 0x08
class tnfs_sortopt:
    NONE = 0x01
    CASE = 0x02
    DESCENDING = 0x04
    MODIFIED = 0x08
    SIZE = 0x10
TNFS_DIRSTATUS_EOF = 0x01

## This appears to be the only TNFS thing that doesn't match Linux. I wonder why...
class tnfs_flag:
    O_RDONLY = 0x0001
    O_WRONLY = 0x0002
    O_RDWR   = 0x0003
    O_APPEND = 0x0008
    O_CREAT  = 0x0100
    O_TRUNC  = 0x0200
    O_EXCL   = 0x0400

def flagsToTNFS(flags):
    tnfs_flags = 0
    if flags & 0x03 == os.O_RDONLY:
        tnfs_flags |= tnfs_flag.O_RDONLY
    elif flags & 0x03 == os.O_WRONLY:
        tnfs_flags |= tnfs_flag.O_WRONLY
    elif flags & 0x03 == os.O_RDWR:
        tnfs_flags |= tnfs_flag.O_RDWR

    if flags & os.O_APPEND:
        tnfs_flags |= tnfs_flag.O_APPEND
    if flags & os.O_CREAT:
        tnfs_flags |= tnfs_flag.O_CREAT
    if flags & os.O_EXCL:
        tnfs_flags |= tnfs_flag.O_EXCL
    if flags & os.O_TRUNC:
        tnfs_flags |= tnfs_flag.O_TRUNC

    return tnfs_flags

class MessageBase:
    TnfsCmd = None
    def __init__(self):
        self.setSession(None).setRetry(0).setCommand(self.TnfsCmd)

    def __repr__(self):
        return f"0x{self.command:x}/{self.__class__}"

    def setSession(self, conn_id):
        self.conn_id = conn_id
        return self

    def setRetry(self, retry):
        self.retry = retry
        return self

    def setCommand(self, command):
        self.command = command
        return self

    def toWire(self):
        ret = b"".join([struct.pack("<HBB", self.conn_id, self.retry, self.command), self.do_ExtraToWire(), self.do_DataToWire()])
        return ret

    def fromWire(self, data):
        conn_id, retry, command = struct.unpack("<HBB", data[:4])
        if command != self.TnfsCmd:
            raise ValueError("Wire data isn't for this command")

        self.setSession(conn_id).setRetry(retry)
        data_pos = self.do_ExtraFromWire(data[4:])
        self.do_DataFromWire(data[4 + data_pos:])
        return self

    def do_ExtraToWire(self):
        return b""

    def do_ExtraFromWire(self, data):
        return 0

    def do_DataToWire(self):
        return b""

    def do_DataFromWire(self, data):
        pass


class Command(MessageBase):
    def __init__(self):
        MessageBase.__init__(self)

class Response(MessageBase):
    def __init__(self):
        MessageBase.__init__(self)
        self.setReply(0)

    def setReply(self, reply):
        self.reply = reply
        return self

    def do_ExtraToWire(self):
        return struct.pack("B", self.reply)

    def do_ExtraFromWire(self, data):
        self.setReply(struct.unpack("B", data[0:1])[0])
        return 1

class Mount(Command):
    TnfsCmd = 0x00
    def __init__(self):
        Command.__init__(self)
        self.setVersion((1, 2)).setLocation(None).setUserPassword("", "")

    def setVersion(self, version):
        self.ver_maj, self.ver_min = version
        return self

    def setLocation(self, location):
        self.location = location
        return self

    def setUserPassword(self, user, password):
        self.user = user
        self.password = password
        return self

    def setSession(self, session):
        return Command.setSession(self, 0)

    def do_DataToWire(self):
        return struct.pack("BB", self.ver_min, self.ver_maj) + f"{self.location}\0{self.user}\0{self.password}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        ver_min, ver_maj = struct.unpack("BB", data[0:2])

        pos = 2
        location, pos = getCstr(data, pos)
        user, pos = getCstr(data, pos)
        password, pos = getCstr(data, pos)
        self.setVersion((ver_maj, ver_min)).setLocation(location).setUserPassword(user, password)

class MountResponse(Response):
    TnfsCmd = Mount.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setVersion((0, 0)).setRetryDelay(None)

    def setVersion(self, version):
        self.ver_maj, self.ver_min = version
        return self

    def setRetryDelay(self, delay):
        self.retry_delay = delay
        return self

    def do_DataToWire(self):
        return struct.pack("BB", self.ver_min, self.ver_maj) + (struct.pack("<H", self.retry_delay) if self.reply == 0 else b"")

    def do_DataFromWire(self, data):
        version_min, version_maj = struct.unpack("BB", data[:2])
        retry_delay = struct.unpack("<H", data[2:])[0] if self.reply == 0 else None
        self.setVersion((version_maj, version_min)).setRetryDelay(retry_delay)

class Umount(Command):
    TnfsCmd = 0x01

class UmountResponse(Response):
    TnfsCmd = Umount.TnfsCmd

class OpenDir(Command):
    TnfsCmd = 0x10
    def __init__(self):
        Command.__init__(self)
        self.setPath(None)

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0])

class OpenDirResponse(Response):
    TnfsCmd = OpenDir.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setHandle(None)
        self.setReply(255)

    def setHandle(self, handle):
        self.handle = handle
        return self

    def do_DataToWire(self):
        return struct.pack("B", self.handle) if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        self.setHandle(struct.unpack("B", data[0:1])[0] if self.reply == 0 else None)

class ReadDir(Command):
    TnfsCmd = 0x11
    def __init__(self):
        Command.__init__(self)
        self.setHandle(None)

    def setHandle(self, handle):
        self.handle = handle
        return self

    def do_DataToWire(self):
        return struct.pack("B", self.handle)

    def do_DataFromWire(self, data):
        self.setHandle(*struct.unpack("B", data[0:1]))

class ReadDirResponse(Response):
    TnfsCmd = ReadDir.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setPath(None)

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return (f"{self.path}\0").encode("utf-8") if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0] if self.reply == 0 else None)

class CloseDir(Command):
    TnfsCmd = 0x12
    def __init__(self):
        Command.__init__(self)
        self.setHandle(None)

    def setHandle(self, handle):
        self.handle = handle
        return self

    def do_DataToWire(self):
        return struct.pack("B", self.handle)

    def do_DataFromWire(self, data):
        self.setHandle(*struct.unpack("B", data[0:1]))

class CloseDirResponse(Response):
    TnfsCmd = CloseDir.TnfsCmd

class MkDir(Command):
    TnfsCmd = 0x13
    def __init__(self):
        Command.__init__(self)
        self.setPath(None)

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0])

class MkDirResponse(Response):
    TnfsCmd = MkDir.TnfsCmd

class RmDir(Command):
    TnfsCmd = 0x14
    def __init__(self):
        Command.__init__(self)
        self.setPath(None)

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0])

class RmDirResponse(Response):
    TnfsCmd = RmDir.TnfsCmd

class OpenDirX(Command):
    TnfsCmd = 0x17
    def __init__(self):
        Command.__init__(self)
        self.setPath(None)
        self.setDirOptions(0)
        self.setSortOptions(0)
        self.setMaxResults(0xffff)
        self.setPattern("")

    def setPath(self, path):
        self.path = path
        return self

    def setPattern(self, pattern):
        self.pattern = pattern
        return self

    def setDirOptions(self, dirOptions):
        self.dirOptions = dirOptions
        return self

    def setSortOptions(self, sortOptions):
        self.sortOptions = sortOptions
        return self

    def setMaxResults(self, maxResults):
        self.maxResults = maxResults
        return self

    def do_DataToWire(self):
        return struct.pack("<BBH", self.dirOptions, self.sortOptions, self.maxResults) + f"{self.pattern}\0{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0])

class OpenDirXResponse(Response):
    TnfsCmd = OpenDirX.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setHandle(None)
        self.setReply(255)
        self.setEntries(0)

    def setHandle(self, handle):
        self.handle = handle
        return self

    def setEntries(self, entries):
        self.entries = entries
        return self

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return struct.pack("B", self.handle) if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        if len(data) < 3:
            return None
        handle, entries = struct.unpack("<BH", data[0:3])
        if self.reply != 0:
            return None
        self.setHandle(handle).setEntries(entries).setPath(getCstr(data[3:], 0)[0])

class ReadDirX(Command):
    TnfsCmd = 0x18
    def __init__(self):
        Command.__init__(self)
        self.setHandle(None)
        # 0 = Maximum possible
        self.setMaxEntries(0)

    def setHandle(self, handle):
        self.handle = handle
        return self

    def setMaxEntries(self, maxEntries):
        self.maxEntries = maxEntries
        return self

    def do_DataToWire(self):
        return struct.pack("BB", self.handle, self.maxEntries)

    def do_DataFromWire(self, data):
        self.setHandle(*struct.unpack("B", data[0:1]))

class ReadDirXResponse(Response):
    TnfsCmd = ReadDirX.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setPath(None)
        self.setEntries(None)

    def setPath(self, path):
        self.path = path
        return self

    def setEntries(self, entries):
        self.entries = entries
        return self

    def setStatus(self, status):
        self.status = status
        return self

    def setDpos(self, dpos):
        self.dpos = dpos
        return self

    def do_DataToWire(self):
        return (f"{self.path}\0").encode("utf-8") if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        if self.reply != 0:
            return self.reply, None

        entryCount, status, dpos = struct.unpack("<BBH", data[0:4])
        self.setStatus(status)
        self.setDpos(dpos)
        pos = 4
        entries = []
        for i in range(entryCount):
            flags, size, mtime, ctime = struct.unpack("<BIII", data[pos:pos+13])
            pos += 13
            name, pos = getCstr(data, pos)
            entries.append(DirEntry().setFlags(flags).setSize(size).setCtime(ctime).setMtime(mtime).setName(name))
        return self.setEntries(entries)

class Open(Command):
    TnfsCmd = 0x29
    def __init__(self):
        Command.__init__(self)
        self.setFlags(0).setMode(0).setPath(None)

    def setFlags(self, flags):
        self.flags = flags
        return self

    def setMode(self, mode):
        self.mode = mode
        return self

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return struct.pack("<HH", self.flags, self.mode) + f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        flags, mode = struct.unpack("<HH", data[:4])
        path, _ = getCstr(data, 4)
        self.setFlags(flags).setMode(mode).setPath(path)

class OpenResponse(Response):
    TnfsCmd = Open.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setFD(None)

    def setFD(self, fd):
        self.fd = fd
        return self

    def do_DataToWire(self):
        return struct.pack("B", self.fd) if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        self.setFD(struct.unpack("B", data)[0] if self.reply == 0 else None)

class Read(Command):
    TnfsCmd = 0x21
    def __init__(self):
        Command.__init__(self)
        self.setFD(None).setSize(None)

    def setFD(self, fd):
        self.fd = fd
        return self

    def setSize(self, size):
        self.size = size
        return self

    def do_DataToWire(self):
        return struct.pack("<BH", self.fd, self.size)

    def do_DataFromWire(self, data):
        fd, size = struct.unpack("<BH", data)
        self.setFD(fd).setSize(size)

class ReadResponse(Response):
    TnfsCmd = Read.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setSize(None).setData(None)

    def setSize(self, size):
        self.size = size
        return self

    def setData(self, data):
        self.data = data
        return self

    def do_DataToWire(self):
        return struct.pack("<H", self.size) if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        self.setSize(struct.unpack("<H", data[:2])[0] if self.reply == 0 else None)
        self.setData(data[2:] if self.reply == 0 else None)

class Write(Command):
    TnfsCmd = 0x22
    def __init__(self):
        Command.__init__(self)
        self.setFD(None).setData(None)

    def setFD(self, fd):
        self.fd = fd
        return self

    def setData(self, data):
        self.data = data
        return self

    def do_DataToWire(self):
        return struct.pack("<BH", self.fd, len(self.data)) + self.data

    def do_DataFromWire(self, data):
        fd, size = struct.unpack("<BH", data[:3])
        self.setFD(fd).setData(data[3:])

class WriteResponse(Response):
    TnfsCmd = Write.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setSize(None)

    def setSize(self, size):
        self.size = size
        return self

    def do_DataToWire(self):
        return struct.pack("<H", self.size) if self.reply == 0 else b""

    def do_DataFromWire(self, data):
        self.setSize(struct.unpack("<H", data)[0] if self.reply == 0 else None)

class Close(Command):
    TnfsCmd = 0x23
    def __init__(self):
        Command.__init__(self)
        self.setFD(None)

    def setFD(self, fd):
        self.fd = fd
        return self

    def do_DataToWire(self):
        return struct.pack("B", self.fd)

    def do_DataFromWire(self, data):
        self.setFD(*struct.unpack("B", data))

class CloseResponse(Response):
    TnfsCmd = Close.TnfsCmd

class Stat(Command):
    TnfsCmd = 0x24
    def __init__(self):
        Command.__init__(self)
        self.setPath(None)

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0])

class StatResponse(Response):
    TnfsCmd = Stat.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setMode(None).setUID(0).setGID(0).setSize(None).setAtime(0).setMtime(0).setCtime(0).setUser("anonymous").setGroup("anonymous")

    def setMode(self, mode):
        self.mode = mode
        return self

    def setUID(self, uid):
        self.uid = uid
        return self

    def setGID(self, gid):
        self.gid = gid
        return self

    def setSize(self, size):
        self.size = size
        return self

    def setAtime(self, atime):
        self.atime = atime
        return self

    def setMtime(self, mtime):
        self.mtime = mtime
        return self

    def setCtime(self, ctime):
        self.ctime = ctime
        return self

    def setUser(self, user):
        self.user = user
        return self

    def setGroup(self, group):
        self.group = group
        return self

    def do_DataToWire(self):
        return struct.pack("<HHHIIII", self.mode, self.uid, self.gid, self.size, self.atime, self.mtime, self.ctime) + f"{self.user}\0{self.group}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        if self.reply == 0:
            mode, uid, gid, size, atime, mtime, ctime = struct.unpack("<HHHIIII", data[:22])
            if len(data) > 22:
                pos = 22
                user, pos = getCstr(data, pos)
                group, pos = getCstr(data, pos)
            else:
                user = "anonymous"
                group = "anonymous"
        else:
            mode = uid = gid = size = atime = mtime = ctime = None
            user = "anonymous"
            group = "anonymous"

        self.setMode(mode).setUID(uid).setGID(gid).setSize(size).setAtime(atime).setMtime(mtime).setCtime(ctime).setUser(user).setGroup(group)

class LSeek(Command):
    TnfsCmd = 0x25
    def __init__(self):
        Command.__init__(self)
        self.setFD(None).setSeekType(None).setSeekPosition(None)

    def setFD(self, fd):
        self.fd = fd
        return self

    def setSeekType(self, seektype):
        self.seektype = seektype
        return self

    def setSeekPosition(self, position):
        self.seekposition = position
        return self

    def do_DataToWire(self):
        return struct.pack("<BBi", self.fd, self.seektype, self.seekposition)

    def do_DataFromWire(self, data):
        fd, seektype, seekposition = struct.unpack("<BBi", data)
        self.setFD(fd).setSeekType(seektype).setSeekPosition(seekposition)

class LSeekResponse(Response):
    TnfsCmd = LSeek.TnfsCmd

class Unlink(Command):
    TnfsCmd = 0x26
    def __init__(self):
        Command.__init__(self)
        self.setPath(None)

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        self.setPath(getCstr(data, 0)[0])

class UnlinkResponse(Response):
    TnfsCmd = Unlink.TnfsCmd

class ChMod(Command):
    TnfsCmd = 0x27
    def __init__(self):
        Command.__init__(self)
        self.setMode(None).setPath(None)

    def setMode(self, mode):
        self.mode = mode
        return self

    def setPath(self, path):
        self.path = path
        return self

    def do_DataToWire(self):
        return struct.pack("<H", self.mode) + f"{self.path}\0".encode("utf-8")

    def do_DataFromWire(self):
        mode, _ = struct.unpack("<H", data[:2])
        path = getCstr(data, 2)
        self.setMode(mode).setPath(path)

class ChModResponse(Response):
    TnfsCmd = ChMod.TnfsCmd

class Rename(Command):
    TnfsCmd = 0x28
    def __init__(self):
        Command.__init__(self)
        self.setSourcePath(None).setDestinationPath(None)

    def setSourcePath(self, path):
        self.source = path
        return self

    def setDestinationPath(self, path):
        self.destination = path
        return self

    def do_DataToWire(self):
        return f"{self.source}\0{self.destination}\0".encode("utf-8")

    def do_DataFromWire(self, data):
        pos = 0
        source, pos = getCstr(data, pos)
        destination, pos = getCstr(data, pos)
        self.setSourcePath(source).setDestinationPath(destination)

class RenameResponse(Response):
    TnfsCmd = Rename.TnfsCmd

class Size(Command):
    TnfsCmd = 0x30

class SizeResponse(Response):
    TnfsCmd = Size.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setSize(None)

    def setSize(self, size):
        self.size = size
        return self

    def do_DataToWire(self):
        return struct.pack("<I", self.size)

    def do_DataFromWire(self, data):
        self.setSize(struct.unpack("<I", data)[0] if self.reply == 0 else None)

class Free(Command):
    TnfsCmd = 0x31

class FreeResponse(Response):
    TnfsCmd = Free.TnfsCmd
    def __init__(self):
        Response.__init__(self)
        self.setFree(None)

    def setFree(self, free):
        self.free = free
        return self

    def do_DataToWire(self):
        return struct.pack("<I", self.free)

    def do_DataFromWire(self, data):
        self.setFree(struct.unpack("<I", data)[0] if self.reply == 0 else None)

klasses = [
    Mount,
    Umount,
    OpenDir,
    ReadDir,
    CloseDir,
    MkDir,
    RmDir,
    Open,
    Read,
    Write,
    Close,
    Stat,
    LSeek,
    Unlink,
    ChMod,
    Rename,
    Size,
    Free,
]

Commands = {klass.TnfsCmd: klass for klass in klasses}

def Test(klass, initfunc):
    print("--" + klass.__name__)
    m = klass()
    initfunc(m)

    w = m.toWire()
    print(repr(w))
    m = klass()
    m.fromWire(w)
    w2 = m.toWire()
    print(repr(w2))
    if w == w2:
        print("*Success*")
    else:
        raise RuntimeError(f"Test of 'klass.__name__' failed")

def RunTests():
    Test(Mount, lambda m: m.setSession(0xbeef).setLocation("/home/tnfs").setUserPassword("username", "password"))
    Test(MountResponse, lambda m: m.setSession(0xbeef).setVersion((2, 6)).setRetryDelay(4999))
    Test(MountResponse, lambda m: m.setSession(0xbeef).setReply(255))
    Test(Umount, lambda m: m.setSession(0xbeef))
    Test(UmountResponse, lambda m: m.setSession(0xbeef).setReply(255))
    Test(OpenDir, lambda m: m.setSession(0xbeef).setPath("/home/tnfs"))
    Test(OpenDirResponse, lambda m: m.setSession(0xbeef).setReply(0).setHandle(0x1f))
    Test(OpenDirResponse, lambda m: m.setSession(0xbeef).setReply(255))
    Test(ReadDir, lambda m: m.setSession(0xbeef).setHandle(0x1f))
    Test(ReadDirResponse, lambda m: m.setSession(0xbeef).setReply(0).setPath("game.tap"))
    Test(ReadDirResponse, lambda m: m.setSession(0xbeef).setReply(255))
    Test(CloseDir, lambda m: m.setSession(0xbeef).setHandle(0x1f))
    Test(CloseDirResponse, lambda m: m.setSession(0xbeef).setReply(0))
    Test(CloseDirResponse, lambda m: m.setSession(0xbeef).setReply(255))
    # TODO Tests for OpenDirX, ReadDirX

class Session:
    def __init__(self, address):
        self.setSession(None)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(DEFAULT_TIMEOUT)
        self.address = (socket.gethostbyname(address[0]), address[1])
        self.sequence = 0

        reply, ver_maj, ver_min = self.Mount("/")
        self.version = f"{ver_maj}.{ver_min}"

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, traceback):
        if self.session is not None:
            self.Umount()
            self.setSession(None)

    def setSession(self, session):
        self.session = session

    def _SendReceive(self, message):
        #sessionId = self.session if self.session is not None else -1
        #print(f"Session: 0x{sessionId:x}, Sequence: 0x{self.sequence:x}, Message: {repr(message)} ")
        message.setRetry(self.sequence).setSession(self.session)
        #print("Sending:\n" + dumpHex(message.toWire(), 65535))
        self.sock.sendto(message.toWire(), self.address)
        data, _ = self.sock.recvfrom(1024)
        #print("Received:\n" + dumpHex(data, 65535))
        #print(f"Return: {data[4]}")
        self.sequence += 1
        self.sequence %= 256
        return data

    def Mount(self, path):
        try:
            data = self._SendReceive(Mount().setLocation(path))
        except TimeoutError:
            print("TimeoutError: Host did not respond")
            sys.exit(0)
        r = MountResponse().fromWire(data)
        if r.reply == 0:
            self.setSession(r.conn_id)
        return r.reply, r.ver_maj, r.ver_min

    def Umount(self):
        data = self._SendReceive(Umount())
        r = UmountResponse().fromWire(data)
        self.setSession(None)
        return r.reply

    def OpenDir(self, path):
        data = self._SendReceive(OpenDir().setPath(path))
        r = OpenDirResponse().fromWire(data)
        return r.reply, r.handle

    def ReadDir(self, handle):
        data = self._SendReceive(ReadDir().setHandle(handle))
        r = ReadDirResponse().fromWire(data)
        return r.reply, r.path

    def OpenDirX(self, path, pattern, dirOptions, sortOptions, maxResults):
        # DirX is supported from tnfs v1.2
        if self.version < "1.2":
            return None, None, None
        data = self._SendReceive(OpenDirX().setPath(path).setPattern(pattern).setDirOptions(dirOptions).setSortOptions(sortOptions).setMaxResults(maxResults))
        r = OpenDirXResponse().fromWire(data)
        return r.reply, r.handle, r.entries

    def ReadDirX(self, handle):
        data = self._SendReceive(ReadDirX().setHandle(handle))
        r = ReadDirXResponse().fromWire(data)
        return r.reply, r.entries

    def CloseDir(self, handle):
        data = self._SendReceive(CloseDir().setHandle(handle))
        r = CloseDirResponse().fromWire(data)
        return r.reply

    def MkDir(self, path):
        data = self._SendReceive(MkDir().setPath(path))
        r = MkDirResponse().fromWire(data)
        return r.reply

    def RmDir(self, path):
        data = self._SendReceive(RmDir().setPath(path))
        r = RmDirResponse().fromWire(data)
        return r.reply

    def Open(self, path, flags = 0, mode = 0):
        data = self._SendReceive(Open().setPath(path).setFlags(flags).setMode(mode))
        r = OpenResponse().fromWire(data)
        return r.reply, r.fd

    def Read(self, fd, size):
        data_received = bytearray(b"")
        while size > 0:
            data = self._SendReceive(Read().setFD(fd).setSize(size if size <= 512 else 512))
            r = ReadResponse().fromWire(data)
            if r.reply == 0:
                data_received.extend(r.data)
                size -= len(r.data)
            else:
                break
        # Convert bytearray to bytes
        data_received = bytes(data_received)
        if (len(data_received) > 0):
            return 0, data_received
        else:
            return r.reply, None

    def Write(self, fd, data_to_send):
        written = 0
        while written < len(data_to_send):
            data = self._SendReceive(Write().setFD(fd).setData(data_to_send[written:written+512]))
            r = WriteResponse().fromWire(data)
            if r.reply != 0:
                break
            written += r.size
        return r.reply, written

    def Close(self, fd):
        data = self._SendReceive(Close().setFD(fd))
        r = CloseResponse().fromWire(data)
        return r.reply

    def Stat(self, path):
        data = self._SendReceive(Stat().setPath(path))
        r = StatResponse().fromWire(data)
        return r.reply, r

    def LSeek(self, fd, offset, whence):
        data = self._SendReceive(LSeek().setFD(fd).setSeekPosition(offset).setSeekType(whence))
        r = LSeekResponse().fromWire(data)
        return r.reply

    def Unlink(self, path):
        data = self._SendReceive(Unlink().setPath(path))
        r = UnlinkResponse().fromWire(data)
        return r.reply

    def Rename(self, source, destination):
        data = self._SendReceive(Rename().setSourcePath(source).setDestinationPath(destination))
        r = RenameResponse().fromWire(data)
        return r.reply

    def ChMod(self, path, mode):
        data = self._SendReceive(ChMod().setPath(path).setMode(mode))
        r = ChModResponse().fromWire(data)
        return r.reply

    def GetFilesystemSize(self):
        data = self._SendReceive(Size())
        r = SizeResponse().fromWire(data)
        return r.reply, r.size

    def GetFilesystemFree(self):
        data = self._SendReceive(Free())
        r = FreeResponse().fromWire(data)
        return r.reply, r.free

    #----------------------------------------------#
    def ListDir(self, path):
        contents = []
        reply, handle = self.OpenDir(path)
        while reply == 0:
            reply, filename = self.ReadDir(handle)
            if reply == 0:
                contents.append(filename)
        if handle is not None:
            self.CloseDir(handle)

        return contents

    def ListDirX(self, path, pattern, dirOptions, sortOptions, maxResults = 65535):
        contents = []
        reply, handle, numEntries = self.OpenDirX(path, pattern, dirOptions, sortOptions, maxResults)
        if reply is None:
            return None
        while reply == 0 and numEntries > 0:
            reply, entries = self.ReadDirX(handle)
            numEntries -= len(entries)
            if reply == 0:
                contents.extend(entries)
        if handle is not None:
            self.CloseDir(handle)

        return contents

    def GetFile(self, path):
        data = []
        reply, fd = self.Open(path)
        if fd is None:
            return None
        while reply == 0:
            reply, chunk = self.Read(fd, 4096)
            if reply == 0:
                data.append(chunk)
        self.Close(fd)
        return b"".join(data)

    def PutFile(self, path, data):
        reply, fd = self.Open(path, tnfs_flag.O_WRONLY | tnfs_flag.O_CREAT | tnfs_flag.O_TRUNC, 0o600)
        if fd is None:
            print("Access denied")
            return
        pos = 0
        while pos < len(data):
            self.Write(fd, data[pos:pos + 4096])
            pos += 4096
        self.Close(fd)

if __name__ == "__main__":
    # RunTests()

    address = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST, int(sys.argv[2]) if len(sys.argv) > 2 else 16384)
    print(f"Connecting to {address[0]}:{address[1]}...")
    # Initial command
    command = ["ls"]
    cwd = "/"
    with Session(address) as S:
        print(f"Remote server is version {S.version}")
        while True:
            # Handle ls aliases
            if len(command) > 0 and command[0] == "l":
                command[0] = "ls"
                if len(command) < 2 or command[1] != "-l":
                    command.insert(1, "-l")
            elif len(command) > 0 and command[0] == "lx":
                command[0] = "ls"
                command.insert(1, "-l")
                command.insert(1, "-x")

            if len(command) == 0:
                pass
            elif command[0] in ("q", "quit"):
                print("Bye!")
                break
            elif command[0] in ("h", "?", "help"):
                printHelp()
            elif command[0] == "ls" or command[0] == "dir":
                long_listing = False
                use_extdir = False
                try:
                    idx = command.index("-l")
                    command.pop(idx)
                    long_listing = True
                except ValueError:
                    pass

                try:
                    idx = command.index("-x")
                    command.pop(idx)
                    use_extdir = True
                except ValueError:
                    pass

                # normpath on Windows uses backslash, which Linux server hosts don't like
                path = os.path.normpath(cwd[1:] + "/" + command[1] if len(command) > 1 else cwd).replace("\\", "/")

                size = free = None
                if use_extdir:
                    pattern = command[2] if len(command) > 2 else ""
                    # TODO Implement dirOptions and sortOptions
                    dirOptions = 0
                    sortOptions = 0
                    files = S.ListDirX(path, pattern, dirOptions, sortOptions, 65535)
                    listing = []
                    if files is not None:
                        if not long_listing:
                            for f in files:
                                listing.append(f.name)
                        else:
                            if len(files) > 0:
                                listing.append(f"{'TYPE':4}  {'SIZE':>10}  {'CREATED':19}  {'MODIFIED':19}  NAME")
                                for f in files:
                                    flags, filesize, ctime, mtime, name = f.getData()
                                    if f.flags & 1:
                                        filetype = "dir"
                                    else:
                                        filetype = "file"
                                    ctimeStr = strftime("%Y-%m-%d %H:%M:%S", ctime)
                                    mtimeStr = strftime("%Y-%m-%d %H:%M:%S", mtime)
                                    listing.append(f"{filetype:4}  {filesize:>10}  {ctimeStr}  {mtimeStr}  {name}{'/' if f.flags & 1 else ''}")
                    else:
                        print("Extended listing not supported by server.")
                else:
                    files = sorted(S.ListDir(path))
                    # Disabled - Commands currently not implemented in server
                    #_, size = S.GetFilesystemSize()
                    #_, free = S.GetFilesystemFree()

                    listing = []
                    if not long_listing:
                        for filename in files:
                            listing.append(filename)
                    else:
                        if len(files) > 0:
                            listing.append(f"{'TYPE':5} {'PERM':5} {'SIZE':8} {'USER':5} {'GROUP':5} NAME")
                            for filename in files:
                                _, filestat = S.Stat(fullPath(path, filename))
                                if stat.S_ISREG(filestat.mode):
                                    filetype = "file"
                                elif stat.S_ISDIR(filestat.mode):
                                    filetype = "dir"
                                else:
                                    filetype = "other"
                                listing.append(f"{filetype:5} {filestat.mode & 0x7777:>05o} {filestat.size:>8} {filestat.uid:>5} {filestat.gid:>5} {filename}")

                print(f"Contents of {path}:")
                for entry in listing:
                    print(f"    {entry}")
                if size is not None:
                    print(f"Size: {size} KB")
                if free is not None:
                    print(f"Free: {free} KB")
            elif command[0] == "cd":
                if len(command) == 2:
                    path = command[1]
                    cwd = fullPath(cwd, path)
                else:
                    print("Syntax: cd <path>")
            elif command[0] == "lcd":
                if len(command) == 2:
                    try:
                        os.chdir(command[1])
                    except OSError as err:
                        print(f"Error setting current directory: {err}")
                    print(f"Current local directory is now '{os.getcwd()}'")
                else:
                    print("Syntax: lcd <path>")
            elif command[0] == "pwd":
                print(cwd)
            elif command[0] == "mkdir":
                if len(command) == 2:
                    path = fullPath(cwd, command[1])
                    S.MkDir(path)
                else:
                    print("Syntax: mkdir <path>")
            elif command[0] == "rmdir":
                if len(command) == 2:
                    path = fullPath(cwd, command[1])
                    S.RmDir(path)
                else:
                    print("Syntax: rmdir <path>")
            elif command[0] == "rm":
                if len(command) == 2:
                    path = fullPath(cwd, command[1])
                    S.Unlink(path)
                else:
                    print("Syntax: rm <remote filename>")
            elif command[0] in ["get", "cat", "dump"]:
                if len(command) in (2, 3):
                    print(f"Downloading '{command[1]}'")
                    source = fullPath(cwd, command[1])
                    destination = command[2] if len(command) == 3 else os.path.basename(source)
                    data = S.GetFile(source)
                    if data is not None:
                        if command[0] == "cat":
                            print(data.decode("iso-8859-15"))
                        elif command[0] == "dump":
                            print(dumpHex(data, DUMP_MAX_BYTES))
                        else:
                            try:
                                with open(destination, "wb", 0o600) as f:
                                    f.write(data)
                            except Exception as err:
                                print(f"Error when writing local file: {err}")
                    else:
                        print("Download failed (no data)")
                else:
                    print("Syntax: get <remote filename> [<local filename>]")
            elif command[0] == "put":
                if len(command) in (2, 3):
                    print(f"Uploading '{command[1]}'")
                    source = command[1]
                    destination = fullPath(cwd, (command[2] if len(command) == 3 else os.path.basename(source)))
                    try:
                        with open(source, "rb") as f:
                            data = f.read()
                        S.PutFile(destination, data)
                    except Exception as err:
                        print(f"Error when opening local file: {err}")
                else:
                    print("Syntax: put <local filename> [<remote filename>]")
            else:
                print(f"Unknown command '{command}'")
            try:
                command = shlex.split(input(f"{cwd}> ").strip().replace("\\","\\\\"), posix=True)
            except (EOFError, KeyboardInterrupt):
                print("quit")
                command = ["quit"]
