package de.infsec.tpl.hashtree.node;

import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.HashUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;


public class Node implements Serializable {
    private static final long serialVersionUID = 6690771073564531337L;

    //public HashCode hah;
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

//    public String getStats() {
/*        StringBuilder sb = new StringBuilder();
        int pNodes = 0;
        int cNodes = 0;
        int mNodes = 0;

        LinkedList<Node> worklist = new LinkedList<Node>();
        worklist.add(this);
        Node curNode;

        while (!worklist.isEmpty()) {
            curNode = worklist.poll();
            worklist.addAll(curNode.childs);

            for (Node n: curNode.childs) {
                if (n instanceof HashTreeOLD.PackageNode)
                    pNodes++;
                else if (n instanceof HashTreeOLD.ClassNode)
                    cNodes++;
                else if (n instanceof HashTreeOLD.MethodNode)
                    mNodes++;
            }
        }

        sb.append("Node stats:\n");
        sb.append(Utils.INDENT + "- contains " + mNodes   + " method hashes.\n");
        sb.append(Utils.INDENT + "- contains " + cNodes    + " clazz hashes.\n");
        sb.append(Utils.INDENT + "- contains " + pNodes + " package hashes.");

        return sb.toString();
    }
*/




}
