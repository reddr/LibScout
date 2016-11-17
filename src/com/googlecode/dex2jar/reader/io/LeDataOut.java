package com.googlecode.dex2jar.reader.io;

import java.io.IOException;
import java.io.OutputStream;

public class LeDataOut implements DataOut {

    public LeDataOut(OutputStream os) {
        super();
        this.os = os;
    }

    private OutputStream os;

    @Override
    public void writeByte(int v) throws IOException {
        os.write(v);
    }

    @Override
    public void writeShort(int v) throws IOException {
        os.write(v);
        os.write(v >> 8);
    }

    @Override
    public void writeInt(int v) throws IOException {
        os.write(v);
        os.write(v >> 8);
        os.write(v >> 16);
        os.write(v >>> 24);
    }

    @Override
    public void writeBytes(byte[] bs)throws IOException {
        os.write(bs);
    }

}
