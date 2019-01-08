package de.infsec.tpl.hashtree.node;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


public class ClassNode extends Node implements Serializable {
    private static final long serialVersionUID = 7790771073564531337L;

    public String clazzName;

    public ClassNode(byte[] hash, String clazzName) {
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

        return Arrays.equals(((Node) obj).hash, this.hash);
    }

    @Override
    public String toString() {
        return "CNode(" + clazzName + ")";
    }
}
