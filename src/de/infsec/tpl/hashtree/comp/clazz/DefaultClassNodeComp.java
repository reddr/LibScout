package de.infsec.tpl.hashtree.comp.clazz;

import com.ibm.wala.classLoader.IClass;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.node.ClassNode;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;

public class DefaultClassNodeComp implements IClassNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);

    @Override
    public ClassNode comp(Collection<? extends Node> methodNodes, IClass clazz, boolean prune) {

        // TODO verboseness (store classnames)
        boolean verbose = false;
        String className = verbose ? WalaUtils.simpleName(clazz) : "";

        // default behaviour, just create hash from child nodes
        ClassNode cn = new ClassNode(HashTree.compNode(methodNodes, true).hash, className);
        if (!prune) cn.childs = new ArrayList<>(methodNodes);

        return cn;
    }

}
