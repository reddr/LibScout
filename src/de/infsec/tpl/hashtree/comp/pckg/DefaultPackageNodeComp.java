package de.infsec.tpl.hashtree.comp.pckg;

import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.hashtree.node.PackageNode;
import de.infsec.tpl.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;

public class DefaultPackageNodeComp implements IPackageNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);
    public final String EMPTY = "PACKAGE_NO_CLASSES_CONST";

    @Override
    public PackageNode comp(Collection<? extends Node> classNodes, String packageName, IClassHierarchy cha, boolean prune) {

        // TODO verboseness (store pckgname)
        boolean verbose = false;
        String className = verbose ? packageName : "";

        // if there are no methods, generate a hash from a constant string to keep that class
        if (classNodes == null || classNodes.isEmpty()) {
            logger.trace(Utils.INDENT + ">> No classes found for package: " + packageName);
            return new PackageNode(HashTree.getHasher().putBytes(EMPTY.getBytes()).hash(), packageName);
        }

        // default behaviour, just create hash from child nodes
        PackageNode pn = new PackageNode(HashTree.compNode(classNodes, false).hash, packageName);
        if (!prune) pn.childs = new ArrayList<>(classNodes);

        return pn;
    }
}
