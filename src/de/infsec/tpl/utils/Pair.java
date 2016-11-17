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

/**
 * A simple Pair implementation
 * @author Erik Derr
 *
 * @param <F>  first object
 * @param <S>  second object
 */
public class Pair<F,S> {
	  private final F first;
	  private final S second;

	  public Pair(F first, S second) {
		  this.first = first;
		  this.second = second;
	  }

	  public static <F,S> Pair<F,S> create(F first, S second) {
		  return new Pair<F,S>(first, second);
	  }
	  
	  public F first() { return this.first; }
	  public S second() { return this.second; }

	  @Override
	  public int hashCode() { return first.hashCode() ^ second.hashCode(); }

	  @Override
	  @SuppressWarnings("unchecked")
	  public boolean equals(Object o) {
		  if (o == null) return false;
		  if (!(o instanceof Pair<?,?>)) return false;
	  
		  Pair<F,S> pair = (Pair<F,S>) o;
		  return this.first.equals(pair.first()) &&
				 this.second.equals(pair.second());
	  }
	  
	  public boolean matches(F first, S second) {
		  return this.first.equals(first) && this.second.equals(second);
	  }
	  
	  @Override
	  public String toString() {
		  return "<" + this.first.toString() + ", " + this.second.toString() + ">";
	  }
}
