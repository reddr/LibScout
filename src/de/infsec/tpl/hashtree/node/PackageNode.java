package de.infsec.tpl.hashtree.node;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


public class PackageNode extends Node implements Serializable {
    private static final long serialVersionUID = 3390771073564531337L;
    public String packageName;

    public PackageNode(byte[] hash, String packageName) {
        super(hash);
        this.packageName = packageName;
    }

  /*  @Override
    public void debug() {
        logger.info("Debug PackageNode: " + packageName + " (childs: " + childs.size() + ",  " + Hash.hash2Str(hash) + ")");
        for (Node n: this.childs) {
            HashTreeOLD.ClassNode cn = (HashTreeOLD.ClassNode) n;
            logger.info(Utils.INDENT + "- " + cn.clazzName + "  ::  " + cn.numberOfChilds() + "  ::  " + Hash.hash2Str(cn.hash));
//				cn.debug();
        }
    }
*/

    public List<ClassNode> getClassNodes() {
        return this.childs.stream()
            .map(mn -> (ClassNode) mn)
            .collect(Collectors.toList());
    }

    // TODO
    public List<MethodNode> getMethodNodes() {
        return this.childs.stream()
            .map(cn -> cn.childs)
            .flatMap(Collection::stream)
            .map(mn -> ((MethodNode) mn))
            .collect(Collectors.toList());
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PackageNode))
            return false;

        return Arrays.equals(((Node) obj).hash, this.hash);
    }

    @Override
    public String toString() {
        return "PNode(" + packageName + ")";
    }
}
