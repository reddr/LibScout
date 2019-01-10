package de.infsec.tpl.hashtree.comp.clazz;

import com.ibm.wala.classLoader.IClass;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.ClassNode;
import de.infsec.tpl.hashtree.node.Node;

import java.util.Collection;

public interface IClassNodeComp {
    ClassNode comp(Collection<? extends Node> methodNodes, IClass clazz, TreeConfig config);
}
