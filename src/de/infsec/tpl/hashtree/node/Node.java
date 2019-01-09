package de.infsec.tpl.hashtree.node;

import de.infsec.tpl.hashtree.HashUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;


public class Node implements Serializable {
    private static final long serialVersionUID = 6690771073564531337L;

    public byte[] hash;
    public List<Node> childs;
    public TreeSet<Short> versions;

    public Node(byte[] hash) {
        this.hash = hash;
        this.childs = new ArrayList<>();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Node))
            return false;

        return Arrays.equals(((Node) obj).hash, this.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash) + childs.size();
    }

    @Override
    public String toString() {
        return HashUtils.hash2Str(this.hash);
    }

    public int numberOfChilds() {
        return this.childs.size();
    }

    public boolean isLeaf() {
        return childs.isEmpty();
    }

    public boolean isMultiVersionNode() {
        return versions != null && !versions.isEmpty();
    }
}
