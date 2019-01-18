package de.infsec.tpl.hashtree;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import de.infsec.tpl.hash.AccessFlags;
import de.infsec.tpl.utils.Utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

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

    @Override
    public String toString() {
        List<String> l = new ArrayList<>();
        if (keepPackageNames) l.add("PN");
        if (keepClassNames) l.add("CN");
        if (keepMethodSignatures) l.add("MSIG");
        String keep = l.isEmpty()? "" : Utils.join(l, "|");

        l = new ArrayList<>();
        if (pruneClasses) l.add("CN");
        if (pruneMethods) l.add("MSIG");
        String prune = l.isEmpty()? "" : Utils.join(l, "|");

        return hf.toString()
            + " | Flags: " + accessFlagsFilter
            + (keep.isEmpty()? "" : " | Keep: " + keep)
            + (prune.isEmpty()? "" : " | Prune: " + prune);
    }
}