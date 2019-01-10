package de.infsec.tpl.hashtree.comp.method;

import com.ibm.wala.classLoader.IMethod;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.MethodNode;

public interface IMethodNodeComp {
    MethodNode comp(IMethod m, TreeConfig config);
}
