package de.infsec.tpl.hashtree.comp.clazz;

import com.ibm.wala.classLoader.IClass;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.ClassNode;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.utils.WalaUtils;

import java.util.ArrayList;
import java.util.Collection;

public class DefaultClassNodeComp implements IClassNodeComp {

    @Override
    public ClassNode comp(Collection<? extends Node> methodNodes, IClass clazz, TreeConfig config) {
        String className = config.keepClassNames ? WalaUtils.simpleName(clazz) : "";

        // default behaviour, just create hash from child nodes
        ClassNode cn = new ClassNode(HashTree.compNode(methodNodes, true, config.getHasher()).hash, className);
        if (!config.pruneMethods) cn.childs = new ArrayList<>(methodNodes);

        return cn;
    }

}
