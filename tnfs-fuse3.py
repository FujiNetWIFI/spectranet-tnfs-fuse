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

import fuse
fuse.fuse_python_api = (0, 2)

from fuse import Fuse
from time import time

import stat
import os
import errno

import tnfs_client3

def getParts(path):
	if path == '/':
		return [['/']]
	else:
		return path.split('/')

class TNFS(Fuse):
	def __init__(self, *args, **kw):
		Fuse.__init__(self, *args, **kw)
		print("Init complete.")

	def main(self, *a, **kw):
		self.file_class = TNFS_File
		return Fuse.main(self, *a, **kw)

	def fsinit(self):
		if self.address.count(':') == 0:
			self.address += ":16384"
		address, port = self.address.split(':')
		port = int(port)

		global TnfsSession

		TnfsSession = tnfs_client.Session((address, port))
		print(f"TNFS Session started with id {TnfsSession.session}")


	def getattr(self, path):
		print("*** getattr", path)
		st = fuse.Stat()
		if path == "/":
			st.st_nlink = 2
			st.st_mode = stat.S_IFDIR | 0o755
		else:
			reply, tnfs_st = TnfsSession.Stat(path)
			if reply != 0:
				return -errno.ENOENT
			st.st_nlink = 1
			st.st_mode = tnfs_st.mode
			st.st_size = tnfs_st.size
			st.st_atime = tnfs_st.atime
			st.st_mtime = tnfs_st.mtime
			st.st_ctime = tnfs_st.ctime

		return st

	def readdir(self, path, offset):
		for e in TnfsSession.ListDir(path):
			yield fuse.Direntry(e)

	def unlink(self, path):
		reply = TnfsSession.Unlink(path)
		return -reply

	def rename(self, oldpath, newpath):
		reply = TnfsSession.Rename(oldpath, newpath)
		return -reply

## Freezes the mount point (tnfsd is not replying)
#	def chmod(self, path, mode):
#		reply = TnfsSession.ChMod(path, mode)
#		return -reply

class TNFS_File(object):
	def __init__(self, path, flags, *mode):
		tnfs_flags = tnfs_client.flagsToTNFS(flags)
		reply, fd = TnfsSession.Open(path, tnfs_flags, *mode)
		if reply != 0:
			raise IOError(reply, os.strerror(reply))
		self.fd = fd

		self.direct_io = False
		self.keep_cache = False

	def flush(self):
		pass

	def release(self, path):
		reply = TnfsSession.Close(self.fd)
		return -reply

	def read(self, length, offset):
		reply = TnfsSession.LSeek(self.fd, offset, os.SEEK_SET)
		if reply != 0:
			raise IOError(reply, "[LSeek]" + os.strerror(reply))
		reply, data = TnfsSession.Read(self.fd, length)
		if reply != 0:
			raise IOError(reply, "[Read]" + os.strerror(reply))
		return data

	def write(self, buf, offset):
		reply = TnfsSession.LSeek(self.fd, offset, os.SEEK_SET)
		if reply != 0:
			raise IOError(reply, os.strerror(reply))
		reply, written = TnfsSession.Write(self.fd, buf)
		if reply != 0:
			raise IOError(reply, os.strerror(reply))
		return written

if __name__ == "__main__":
	fs = TNFS()
	fs.multithreaded = 0
	fs.parser.add_option(mountopt = "address", help = "<Address>[:<Port>] of the TNFS server. Port defaults to 16384 if not specified")
	fs.parse(values = fs, errex = 1)
	fs.main()
