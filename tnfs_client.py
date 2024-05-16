#!/usr/bin/python

# The MIT License
#
# Copyright (c) 2012 Radu Cristescu
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

def getCstr(data, pos):
	end = data.find("\0", pos)
	if end == -1:
		return None, None
	string = data[pos:end]
	return string, pos + len(string) + 1

def fullPath(cwd, path):
	result = os.path.normpath(cwd + "/" + path) if path[0] != "/" else path

	## http://stackoverflow.com/questions/7816818/why-doesnt-os-normapath-collapse-a-leading-double-slash
	## It doesn't hurt having a double slash, but it looks ugly and inconsistent, so we clean it up
	if result[:2] == "//":
		result = result[1:]

	return result

## This appears to be the only TNFS thing that doesn't match Linux. I wonder why...
class tnfs_flag(object):
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

class MessageBase(object):
	TnfsCmd = None
	def __init__(self):
		self.setSession(None).setRetry(0).setCommand(self.TnfsCmd)

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
		return struct.pack("<HBB", self.conn_id, self.retry, self.command) + self.do_ExtraToWire() + self.do_DataToWire()

	def fromWire(self, data):
		conn_id, retry, command = struct.unpack("<HBB", data[:4])
		if command != self.TnfsCmd:
			raise ValueError("Wire data isn't for this command")

		self.setSession(conn_id).setRetry(retry)
		data_pos = self.do_ExtraFromWire(data[4:])
		self.do_DataFromWire(data[4 + data_pos:])
		return self

	def do_ExtraToWire(self):
		return ""

	def do_ExtraFromWire(self, data):
		return 0

	def do_DataToWire(self):
		return ""

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
		self.setReply(*struct.unpack("B", data[0]))
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
		return struct.pack("BB", self.ver_min, self.ver_maj) + "%s\0%s\0%s\0" % (self.location, self.user, self.password)

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
		return struct.pack("BB", self.ver_min, self.ver_maj) + (struct.pack("<H", self.retry_delay) if self.reply == 0 else "")

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
		return self.path + "\0"

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
		return struct.pack("B", self.handle) if self.reply == 0 else ""

	def do_DataFromWire(self, data):
		self.setHandle(struct.unpack("B", data[0])[0] if self.reply == 0 else None)

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
		self.setHandle(*struct.unpack("B", data[0]))

class ReadDirResponse(Response):
	TnfsCmd = ReadDir.TnfsCmd
	def __init__(self):
		Response.__init__(self)
		self.setPath(None)

	def setPath(self, path):
		self.path = path
		return self

	def do_DataToWire(self):
		return self.path  + "\0" if self.reply == 0 else ""

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
		self.setHandle(*struct.unpack("B", data[0]))

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
		return self.path + "\0"

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
		return self.path + "\0"

	def do_DataFromWire(self, data):
		self.setPath(getCstr(data, 0)[0])

class RmDirResponse(Response):
	TnfsCmd = RmDir.TnfsCmd

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
		return struct.pack("<HH", self.flags, self.mode) + self.path + "\0"

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
		return struct.pack("B", self.fd) if self.reply == 0 else ""

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
		return struct.pack("<H", self.size) if self.reply == 0 else ""

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
		return struct.pack("<H", self.size) if self.reply == 0 else ""

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
		return self.path + "\0"

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
		return struct.pack("<HHHIIII", self.mode, self.uid, self.gid, self.size, self.atime, self.mtime, self.ctime) + self.user + "\0" + self.group + "\0"

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
		return self.path + "\0"

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
		return struct.pack("<H", self.mode) + self.path + "\0"

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
		return self.source + "\0" + self.destination + "\0"

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
		raise RuntimeError("Test of '%s' failed" % klass.__name__)

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

class Session(object):
	def __init__(self, address, protocol):
		self.setSession(None)

		if protocol == None or protocol == "tcp":
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.settimeout(30)
			try:
				self.sock.connect((address[0], address[1]))
			except socket.error:
				if protocol == "tcp":
					raise
				else:
					protocol = "udp"

		if protocol == "udp":
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.sock.settimeout(30)
			self.address = (socket.gethostbyname(address[0]), address[1])

		self.sequence = 0
		self.protocol = protocol

		try:
			reply, ver_maj, ver_min = self.Mount("/")
			if self.protocol == None:
				self.protocol = "tcp"
			self.version = "%d.%d" % (ver_maj, ver_min)
			print("Connected via %s." % (self.protocol))
		except Exception:
			if protocol == None:
				return self.__init__(address, "udp")
			else:
				raise

	def __enter__(self):
		return self

	def __exit__(self, ex_type, ex_value, traceback):
		if self.session is not None:
			self.Umount()
			self.setSession(None)

	def setSession(self, session):
		self.session = session

	def _SendReceive(self, message):
		#print "Session: %x, Sequence:%r, Message: %r " % (self.session if self.session is not None else -1, self.sequence, message)
		message.setRetry(self.sequence).setSession(self.session)
		if self.protocol == None or self.protocol == "tcp":
			self.sock.sendall(message.toWire())
			data = self.sock.recv(1024)
		else:
			self.sock.sendto(message.toWire(), self.address)
			data, _ = self.sock.recvfrom(1024)
		#print "Return: %r" % data[4]
		self.sequence += 1
		self.sequence %= 256
		return data

	def Mount(self, path):
		data = self._SendReceive(Mount().setLocation(path))
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
		data_received = []
		while size > 0:
			data = self._SendReceive(Read().setFD(fd).setSize(size if size <= 512 else 512))
			r = ReadResponse().fromWire(data)
			if r.reply == 0:
				data_received.append(r.data)
				size -= len(r.data)
			else:
				break
		data_received = "".join(data_received)
		if (len(data_received) > 0):
			return 0, "".join(data_received)
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
		return "".join(data)

	def PutFile(self, path, data):
		reply, fd = self.Open(path, tnfs_flag.O_WRONLY | tnfs_flag.O_CREAT | tnfs_flag.O_TRUNC, 0600)
		if fd is None:
			print "Access denied"
			return
		pos = 0
		while pos < len(data):
			self.Write(fd, data[pos:pos + 4096])
			pos += 4096
		self.Close(fd)

if __name__ == "__main__":
	#RunTests()

	args = [a for a in sys.argv if not a.startswith('--')]
	address = (args[1] if len(args) > 1 else 'vexed4.alioth.net', int(args[2]) if len(args) > 2 else 16384)
	protocol = None
	if "--tcp" in sys.argv:
		protocol = "tcp"
	elif "--udp" in sys.argv:
		protocol = "udp"
	print("Connecting to {}:{}...".format(address[0], address[1]))

	command = ["ls"]
	cwd = "/"
	with Session(address, protocol) as S:
		print "Remote server is version", S.version
		while True:
			if len(command) == 0:
				pass
			elif command[0] == "quit":
				print "Bye!"
				break
			elif command[0] == "ls" or command[0] == "dir":
				long_listing = False
				if len(command) > 1 and command[1] == "-l":
					command.pop(1)
					long_listing = True
				path = os.path.normpath(cwd[1:] + "/" + command[1] if len(command) > 1 else cwd)

				files = sorted(S.ListDir(path))
				_, size = S.GetFilesystemSize()
				_, free = S.GetFilesystemFree()

				listing = []
				if not long_listing:
					for filename in files:
						listing.append(filename)
				else:
					listing_format = "{0:^15s} {1:0>5o} {2:>15d} {3:>5d} {4:>5d} {5}"
					listing_header = "{0:^15s} {1: ^5s} {2:^15s} {3:>5s} {4:>5s} {5}".format("TYPE", "PERM", "SIZE", "USER", "GROUP", "NAME")
					listing.append(listing_header)
					for filename in files:
						_, filestat = S.Stat(fullPath(path, filename))
						if stat.S_ISREG(filestat.mode):
							filetype = "file"
						elif stat.S_ISDIR(filestat.mode):
							filetype = "directory"
						else:
							filetype = "other"
						details = listing_format.format(filetype, filestat.mode & 07777, filestat.size, filestat.uid, filestat.gid, filename)
						listing.append(details)

				print "Contents of %s:" % path
				for entry in listing:
					print "    " + entry
				if size is not None:
					print "Size: %d KB" % size
				if free is not None:
					print "Free: %d KB" % free
			elif command[0] == "cd":
				if len(command) == 2:
					path = command[1]
					cwd = fullPath(cwd, path)
				else:
					print "Syntax: cd <path>"
			elif command[0] == "pwd":
				print cwd
			elif command[0] == "mkdir":
				if len(command) == 2:
					path = fullPath(cwd, command[1])
					S.MkDir(path)
				else:
					print "Syntax: mkdir <path>"
			elif command[0] == "rmdir":
				if len(command) == 2:
					path = fullPath(cwd, command[1])
					S.RmDir(path)
				else:
					print "Syntax: rmdir <path>"
			elif command[0] == "get":
				if len(command) in (2, 3):
					print "Downloading '%s'" % command[1]
					source = fullPath(cwd, command[1])
					destination = command[2] if len(command) == 3 else os.path.basename(source)
					data = S.GetFile(source)
					if data is not None:
						with open(destination, "w", 0600) as f:
							f.write(data)
					else:
						print "Download failed"
				else:
					print "Syntax: get <remote filename> [<local filename>]"
			elif command[0] == "put":
				if len(command) in (2, 3):
					print "Uploading '%s'" % command[1]
					source = command[1]
					destination = fullPath(cwd, (command[2] if len(command) == 3 else os.path.basename(source)))
					with open(source, "r") as f:
						data = f.read()
					S.PutFile(destination, data)
				else:
					print "Syntax: put <local filename> [<remote filename>]"
			else:
				print "Unknown command '%s'" % command
			try:
				command = raw_input(cwd + "> ").strip().split()
			except (EOFError, KeyboardInterrupt):
				print "quit"
				command = ["quit"]
