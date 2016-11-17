/*
 * Copyright (c) 2009-2012 Panxiaobo
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pxb.android.axml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import com.googlecode.dex2jar.reader.io.DataIn;
import com.googlecode.dex2jar.reader.io.DataOut;

@SuppressWarnings("serial")
class StringItems extends ArrayList<StringItem> {

    byte[] stringData;

    public int getSize() {
        return 5 * 4 + this.size() * 4 + stringData.length + 0;// TODO
    }

    public void prepare() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int i = 0;
        int offset = 0;
        baos.reset();
        Map<String, Integer> map = new HashMap<String, Integer>();
        for (StringItem item : this) {
            item.index = i++;
            String stringData = item.data;
            Integer of = map.get(stringData);
            if (of != null) {
                item.dataOffset = of;
            } else {
                item.dataOffset = offset;
                map.put(stringData, offset);
                int length = stringData.length();
                byte[] data = stringData.getBytes("UTF-16LE");
                baos.write(length);
                baos.write(length >> 8);
                baos.write(data);
                baos.write(0);
                baos.write(0);
                offset += 4 + data.length;
            }
        }
        // TODO
        stringData = baos.toByteArray();
    }

    public void read(DataIn in, int size) throws IOException {
        int trunkOffset = in.getCurrentPosition() - 4;
        int stringCount = in.readIntx();
        int styleOffsetCount = in.readIntx();
        int flags = in.readIntx();
        int stringDataOffset = in.readIntx();
        int stylesOffset = in.readIntx();
        for (int i = 0; i < stringCount; i++) {
            StringItem stringItem = new StringItem();
            stringItem.index = i;
            stringItem.dataOffset = in.readIntx();
            this.add(stringItem);
        }
        Map<Integer, String> stringMap = new TreeMap();
        if (styleOffsetCount != 0) {
            throw new RuntimeException();
            // for (int i = 0; i < styleOffsetCount; i++) {
            // StringItem stringItem = new StringItem();
            // stringItem.index = i;
            // stringItems.add(stringItem);
            // }
        }
        int endOfStringData = stylesOffset == 0 ? size : stylesOffset;
        int base = in.getCurrentPosition();
        if (0 != (flags & AxmlReader.UTF8_FLAG)) {
            for (int p = base; p < endOfStringData; p = in.getCurrentPosition()) {
                int length = (int) in.readLeb128();
                if (length == 0) continue;

                // FIXME: sometimes the length determined above is negative, which causes the stream initializer to
                //        throw an exception. we can set a fixed size here, which should work in most cases
                ByteArrayOutputStream bos = new ByteArrayOutputStream(100);  // orig:   (length + 10);
                for (int r = in.readByte(); r != 0; r = in.readByte()) {
                    bos.write(r);
                }
                String value = new String(bos.toByteArray(), "UTF-8");
                stringMap.put(p - base, value);
            }
        } else {
            for (int p = base; p < endOfStringData; p = in.getCurrentPosition()) {
                int length = in.readShortx();
                byte[] data = in.readBytes(length * 2);
                in.skip(2);
                String value = new String(data, "UTF-16LE");
                stringMap.put(p - base, value);
                // System.out.println(String.format("%08x %s", p - base, value));
            }
        }
        if (stylesOffset != 0) {
            System.err.println("ignore style offset at 0x" + Integer.toHexString(trunkOffset));
        }
        for (StringItem item : this) {
            item.data = stringMap.get(item.dataOffset);
            // System.out.println(item);
        }
    }

    public void write(DataOut out) throws IOException {
        out.writeInt(this.size());
        out.writeInt(0);// TODO
        out.writeInt(0);
        out.writeInt(7 * 4 + this.size() * 4);
        out.writeInt(0);
        for (StringItem item : this) {
            out.writeInt(item.dataOffset);
        }
        out.writeBytes(stringData);
        // TODO
    }
}
