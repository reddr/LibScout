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

import static pxb.android.axml.AxmlVisitor.TYPE_STRING;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import pxb.android.axml.AxmlVisitor.NodeVisitor;
import pxb.android.axml.EmptyAdapter.EmptyNode;

import com.googlecode.dex2jar.reader.io.DataIn;
import com.googlecode.dex2jar.reader.io.LeArrayDataIn;

/**
 * a class to read android axml
 * 
 * @author <a href="mailto:pxb1988@gmail.com">Panxiaobo</a>
 * 
 */
public class AxmlReader {
	public static final NodeVisitor EMPTY_VISITOR = new EmptyNode() {
		@Override
		public NodeVisitor child(String ns, String name) {
			return EMPTY_VISITOR;
		}
	};
	static final int UTF8_FLAG = 0x00000100;
	static final int CHUNK_AXML_FILE = 0x00080003;
	static final int CHUNK_RESOURCEIDS = 0x00080180;
	static final int CHUNK_STRINGS = 0x001C0001;
	static final int CHUNK_XML_END_NAMESPACE = 0x00100101;
	static final int CHUNK_XML_END_TAG = 0x00100103;
	static final int CHUNK_XML_START_NAMESPACE = 0x00100100;
	static final int CHUNK_XML_START_TAG = 0x00100102;
	static final int CHUNK_XML_TEXT = 0x00100104;
	private StringItems stringItems = new StringItems();
	private List<Integer> resourceIds = new ArrayList<Integer>();
	private DataIn in;

	public AxmlReader(byte[] data) {
		this(new LeArrayDataIn(data));
	}

	public AxmlReader(DataIn in) {
		super();
		this.in = in;
	}

	public void accept(final AxmlVisitor documentVisitor) throws IOException {
		DataIn in = this.in;
		int fileSize;
		{
			int type = in.readIntx();
			if (type != CHUNK_AXML_FILE) {
				throw new RuntimeException();
			}
			fileSize = in.readIntx();
		}
		NodeVisitor root = documentVisitor == null ? EMPTY_VISITOR
				: new EmptyNode() {
					@Override
					public NodeVisitor child(String ns, String name) {
						return documentVisitor.first(ns, name);
					}
				};

		NodeVisitor tos = root;
		Stack<NodeVisitor> nvs = new Stack<NodeVisitor>();
		nvs.push(root);

		String name, ns;
		int nameIdx, nsIdx;
		int lineNumber;

		for (int p = in.getCurrentPosition(); p < fileSize; p = in.getCurrentPosition()) {
			int type = in.readIntx();
			int size = in.readIntx();
			switch (type) {
			case CHUNK_XML_START_TAG: {
				{
					lineNumber = in.readIntx();
					in.skip(4);/* 0xFFFFFFFF */
					nsIdx = in.readIntx();
					nameIdx = in.readIntx();
					int flag = in.readIntx();// 0x00140014 ?
					if (flag != 0x00140014) {
						throw new RuntimeException();
					}
					name = stringItems.get(nameIdx).data;
					ns = nsIdx >= 0 ? stringItems.get(nsIdx).data : null;

					tos = tos.child(ns, name);
					if (tos == null) {
						tos = EMPTY_VISITOR;
					}

					nvs.push(tos);
					tos.line(lineNumber);
				}

				int attributeCount = in.readUShortx();
				// int idAttribute = in.readUShortx();
				// int classAttribute = in.readUShortx();
				// int styleAttribute = in.readUShortx();
				in.skip(6);
				if (tos != EMPTY_VISITOR) {
					for (int i = 0; i < attributeCount; i++) {
						nsIdx = in.readIntx();
						nameIdx = in.readIntx();
						in.skip(4);// skip valueString
						int aValueType = in.readIntx() >>> 24;
						int aValue = in.readIntx();
						name = stringItems.get(nameIdx).data;
						ns = nsIdx >= 0 ? stringItems.get(nsIdx).data : null;
						Object value = aValueType == TYPE_STRING ? stringItems
								.get(aValue).data : aValue;
						int resourceId = nameIdx < resourceIds.size() ? resourceIds
								.get(nameIdx) : -1;
						tos.attr(ns, name, resourceId, aValueType, value);
					}
				} else {
					in.skip(5 * 4);
				}
			}
				break;
			case CHUNK_XML_END_TAG: {
				in.skip(size - 8);
				tos.end();
				tos = nvs.pop();
			}
				break;
			case CHUNK_XML_START_NAMESPACE:
				if (documentVisitor == null) {
					in.skip(4 * 4);
				} else {
					lineNumber = in.readIntx();
					in.skip(4);/* 0xFFFFFFFF */
					int prefixIdx = in.readIntx();
					nsIdx = in.readIntx();
					documentVisitor.ns(stringItems.get(prefixIdx).data,
							stringItems.get(nsIdx).data, lineNumber);
				}
				break;
			case CHUNK_XML_END_NAMESPACE:
				in.skip(size - 8);
				break;
			case CHUNK_STRINGS:
				stringItems.read(in, size);
				break;
			case CHUNK_RESOURCEIDS:
				int count = size / 4 - 2;
				for (int i = 0; i < count; i++) {
					resourceIds.add(in.readIntx());
				}
				break;
			case CHUNK_XML_TEXT:
				if (tos == EMPTY_VISITOR) {
					in.skip(20);
				} else {
					lineNumber = in.readIntx();
					in.skip(4);/* 0xFFFFFFFF */
					nameIdx = in.readIntx();
					in.skip(8); /* 00000008 00000000 */
					name = stringItems.get(nameIdx).data;
					tos.text(lineNumber, name);
				}
				break;
			default:
				throw new RuntimeException();
			}
			in.move(p + size);
		}
	}
}
