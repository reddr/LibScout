package de.infsec.tpl.hashtree.node;

import com.google.common.hash.HashCode;


public class MethodNode extends Node {
    public String signature;

    public MethodNode(HashCode hash, String signature) {
        super(hash);
        this.signature = signature;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof MethodNode))
            return false;

        return ((MethodNode) obj).hash.equals(this.hash);
    }

    @Override
    public String toString() {
        return "MNode(" + signature + ")";
    }
}
