package de.infsec.tpl.hashtree.node;

import com.google.common.hash.HashCode;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;


public class Node {
    public HashCode hash;
    public List<Node> childs;
    public TreeSet<Short> versions;

    public Node(HashCode hash) {
        this.hash = hash;
        this.childs = new ArrayList<>();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Node))
            return false;
        return ((Node) obj).hash.equals(this.hash);
    }

    @Override
    public int hashCode() {
        return hash.hashCode() + childs.size();
    }

    @Override
    public String toString() {
        return this.hash.toString();
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
