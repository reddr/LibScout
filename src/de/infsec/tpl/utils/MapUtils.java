/*
 * Copyright (c) 2015-2016  Erik Derr [derr@cs.uni-saarland.de]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package de.infsec.tpl.utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


public class MapUtils {
	/**
	 * Generic add function for maps that contain an list of values.
	 * If the target list does not exist, it is created and the value is
	 * then put in.
	 * @param map
	 * @param key 
	 * @param value
	 */
	@SuppressWarnings("unchecked")
	public static <T,V, L extends List<V>> void addValue(Map<T, L> map, T key, V value) {
		ArrayList<V> valList = map.containsKey(key)? new ArrayList<V>(map.get(key)) : new ArrayList<V>();

		if (!valList.contains(value)) {
			valList.add(value);
			map.put(key, (L) valList);				
		}
	}

	public static <T,V> void addList(Map<T,List<V>> map, T key, List<V> valueList) {
		ArrayList<V> valList = map.containsKey(key)? new ArrayList<V>(map.get(key)) : new ArrayList<V>();

		for (V val: valueList) {
			if (!valList.contains(val)) {
				valList.add(val);
			}
		}
		map.put(key, valList);
	}

	public static <T,V> void addList(Map<T, ArrayList<V>> map, T key, List<V> valueList, int skipEntryIdx) {
		ArrayList<V> valList = map.containsKey(key)? map.get(key) : new ArrayList<V>();

		for (int i = 0; i < valueList.size(); i++) {
			V val = valueList.get(i);
			if (!valList.contains(val) && i != skipEntryIdx) {
				valList.add(val);
			}
		}
		map.put(key, valList);
	}

	
	
	
	/**
	 * Getter function for HashMaps with an arraylist of values.
	 * @param map
	 * @param key
	 * @return the arraylist for the input key or an empty list
	 *         if the key is not existing
	 */
	public static <T,V> ArrayList<V> getList(Map<T,List<V>> map, T key) {
		return map.containsKey(key)? new ArrayList<V>(map.get(key)) : new ArrayList<V>();
	}
	

	/**
	 * Size function for HashMaps with an list of values.
	 * @param map
	 * @return the combined size of all individual lists in the map
	 */
	public static <T,V> int size(Map<T, List<V>> map) {
		int entries = 0;
		for (T key: map.keySet()) entries += map.get(key).size();
		return entries;
	}
	

	/**
	 * Adds a value to a set within a map.
	 * @param map
	 * @param key
	 * @param value
	 */
	public static <T,V> void addToSet(Map<T, Set<V>> map, T key, V value) {
		Set<V> valSet = map.containsKey(key)? map.get(key) : new HashSet<V>();

		if (valSet.add(value)) {
			map.put(key, valSet);				
		}
	}
	
	
}
