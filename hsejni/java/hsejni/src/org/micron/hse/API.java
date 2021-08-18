/**
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Copyright (C) 2015-2021 Micron Technology, Inc.
 */
package org.micron.hse;

public class API {

	public static void loadLibrary() {
		// loadlibrary
		if (System.getProperty("os.name").startsWith("Windows"))
			// Windows
			System.loadLibrary("libhsejni_Library_windows");
		else
			// Linux
			System.loadLibrary("hsejni");
	}

	public long getNativeHandle() {
		return nativeHandle;
	}

	public void setNativeHandle(long nativeHandle) {
		this.nativeHandle = nativeHandle;
	}

	public void init() throws HSEGenException {
		this.init(-1);
	}

	public int put(byte[] key, byte[] value) throws HSEGenException {
		return this.put(nativeHandle, key, value);
	}

	public byte[] get(byte[] key) throws HSEGenException {
		return this.get(nativeHandle, key);
	}

	public int del(byte[] key) throws HSEGenException {
		return this.del(nativeHandle, key);
	}

	public void close() throws HSEGenException {
		this.close(nativeHandle);
	}

	/* [HSE_REVISIT]: Might be good to have a separate interface for
	 * prefixed cursors rather than overloading this one.
	 */
	public void createCursor(String pfx, int pfxlen)
				 throws HSEGenException {
		this.createCursor(nativeHandle, pfx, pfxlen);
	}

	public void destroyCursor() throws HSEGenException {
		this.destroyCursor(nativeHandle);
	}

	public byte[] seek(byte[] key) throws HSEGenException {
		return this.seek(nativeHandle, key);
	}

	public byte[] read() throws HSEGenException, HSEEOFException {
		return this.read(nativeHandle);
	}

	private long nativeHandle;

	// JNI functions

	public native void init(long valBufSize) throws HSEGenException;

	public native void fini() throws HSEGenException;

	public native void open(short dbType, String kvdbHome, String kvsName,
                                String hseConfig) throws HSEGenException;

	public native int close(long handle) throws HSEGenException;

	// TODO: support put options
	public native int put(long handle, byte[] key, byte[] value)
			      throws HSEGenException;

	// TODO: find a way to pass by reference. pass a byte array for example.
	public native byte[] get(long handle, byte[] key)
				 throws HSEGenException;

	public native int del(long handle, byte[] key) throws HSEGenException;

	public native void createCursor(long handle, String pfx, int pfxlen)
					throws HSEGenException;

	public native void destroyCursor(long handle) throws HSEGenException;

	public native byte[] seek(long handle, byte[] key)
				  throws HSEGenException;

	public native byte[] read(long handle)
				  throws HSEGenException, HSEEOFException;
}
