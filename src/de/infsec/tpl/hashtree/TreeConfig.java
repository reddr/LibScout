package de.infsec.tpl.hashtree;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import de.infsec.tpl.hash.AccessFlags;

import java.io.Serializable;

public class TreeConfig implements Serializable {
    private static final long serialVersionUID = 1190771073563431337L;

    public HashFunction hf = Hashing.md5();
    public AccessFlags accessFlagsFilter = AccessFlags.NO_FLAG;

    // verboseness
    public boolean keepPackageNames = true;
    public boolean keepClassNames = false;
    public boolean keepMethodSignatures = false;

    // node pruning
    public boolean pruneClasses = false;
    public boolean pruneMethods = true;


    public Hasher getHasher() {
        return hf.newHasher();
    }
}