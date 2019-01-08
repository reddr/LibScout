package de.infsec.tpl.hashtree.node;

import com.google.common.hash.HashCode;

import java.util.List;
import java.util.stream.Collectors;


public class ClassNode extends Node {
    public String clazzName;

    public ClassNode(HashCode hash, String clazzName) {
        super(hash);
        this.clazzName = clazzName;
    }

    public List<MethodNode> getMethodNodes() {
        return this.childs.stream().map(mn -> (MethodNode) mn).collect(Collectors.toList());
    }

    /*
    @Override
    public void debug() {
        //logger.info("Debug ClassNode: " + clazzName + "  (childs: " + childs.size() + ",  "  + Hash.hash2Human(hash) + ")");
        for (Node n: this.childs) {
            HashTreeOLD.MethodNode mn = (HashTreeOLD.MethodNode) n;
            logger.info(Utils.INDENT2 + "- " + mn.signature + "  ::  " + Hash.hash2Str(mn.hash));
        }
    }*/

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ClassNode))
            return false;

        return ((Node) obj).hash.equals(this.hash);
    }

    @Override
    public String toString() {
        return "CNode(" + clazzName + ")";
    }
}
