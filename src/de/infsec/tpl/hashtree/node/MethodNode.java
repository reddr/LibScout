package de.infsec.tpl.hashtree.node;

import de.infsec.tpl.hashtree.HashUtils;

import java.io.Serializable;
import java.util.Arrays;


public class MethodNode extends Node implements Serializable {
    private static final long serialVersionUID = 5590771073564531337L;
    public String signature;

    public MethodNode(byte[] hash, String signature) {
        super(hash);
        this.signature = signature;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof MethodNode))
            return false;

        return Arrays.equals(((Node) obj).hash, this.hash);
    }

    @Override
    public String toString() {
        return "MNode(" + signature + ")";
    }
}
