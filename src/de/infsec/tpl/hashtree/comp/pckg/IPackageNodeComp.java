package de.infsec.tpl.hashtree.comp.pckg;

import com.ibm.wala.ipa.cha.IClassHierarchy;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.Node;
import de.infsec.tpl.hashtree.node.PackageNode;

import java.util.Collection;

public interface IPackageNodeComp {
    PackageNode comp(Collection<? extends Node> classNodes, String packageName, IClassHierarchy cha, TreeConfig config);
}
