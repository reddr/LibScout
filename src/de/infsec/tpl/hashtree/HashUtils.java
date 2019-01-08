package de.infsec.tpl.hashtree;


import de.infsec.tpl.hashtree.node.Node;

import java.util.Comparator;

public class HashUtils {

    public static String hash2Str(byte[] hash) {
        String format = "%" + (hash.length*2) + "x";
        return String.format(format, new java.math.BigInteger(1, hash));
    }

    public static final NodeComparator comp = new NodeComparator();

    public static class NodeComparator implements Comparator<Node> {
        public NodeComparator() {}

        private int compare(byte[] left, byte[] right) {
            for (int i = 0, j = 0; i < left.length && j < right.length; i++, j++) {
                int a = (left[i] & 0xff);
                int b = (right[j] & 0xff);
                if (a != b) {
                    return a - b;
                }
            }
            return left.length - right.length;
        }

        @Override
        public int compare(Node n0, Node n1) {
            return compare(n0.hash, n1.hash);
        }
    }
}
