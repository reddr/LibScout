package de.infsec.tpl.hashtree.comp.pckg;

import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.hashtree.node.PackageNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;

public class DefaultPackageNodeComp implements IPackageNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);

    @Override
    public PackageNode comp(Collection<? extends Node> classNodes, String packageName, IClassHierarchy cha, boolean prune) {

        // default behaviour, just create hash from child nodes
        PackageNode pn = new PackageNode(HashTree.compNode(classNodes, false).hash, (HashTree.Config.keepPackageNames? packageName : ""));
        if (!prune) pn.childs = new ArrayList<>(classNodes);

        return pn;
    }
}
