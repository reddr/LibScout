package de.infsec.tpl.hashtree.comp.method;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.Descriptor;
import de.infsec.tpl.hashtree.HashTree;
import de.infsec.tpl.hashtree.TreeConfig;
import de.infsec.tpl.hashtree.node.MethodNode;
import de.infsec.tpl.utils.Utils;
import de.infsec.tpl.utils.WalaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SignatureMethodNodeComp implements IMethodNodeComp {
    private static final Logger logger = LoggerFactory.getLogger(HashTree.class);


    @Override
    public MethodNode comp(IMethod m, TreeConfig config) {
        String desc = normalizeAnonymousInnerClassConstructor(m);
        if (desc == null)
            desc = getFuzzyDescriptor(m);

        String signature = config.keepMethodSignatures? m.getSignature() : "";
        return new MethodNode(config.getHasher().putBytes(desc.getBytes()).hash().asBytes(), signature);
    }


    /**
     * This normalization of constructors of anonymous inner classes is due to the fact that
     * (in some cases) the dx compiler adds the superclass of the enclosing class as second parameter,
     * while the javac does not. This results in different hashes for this classes which implies that
     * this library can't be matched exactly although it is the same version. Therefore, this
     * normalization will skip this second argument during generation of the fuzzy descriptor.
     *
     * See example code: method createAdapter() in
     * https://github.com/facebook/facebook-android-sdk/blob/f6c4e4c1062bcc74e5a25b3243f6bee2e32d949e/facebook/src/com/facebook/widget/PlacePickerFragment.java
     *
     * In the disassembled dex the constructor can look like this:
     * <source>
     * method constructor <init>(Lcom/facebook/widget/PlacePickerFragment;Lcom/facebook/widget/PickerFragment;Landroid/content/Context;)V
     *     .locals 0
     *     .param p3, "$anonymous0"    # Landroid/content/Context;
     *
     *     iput-object p1, p0, Lcom/facebook/widget/PlacePickerFragment$1;->this$0:Lcom/facebook/widget/PlacePickerFragment;
     *     invoke-direct {p0, p2, p3}, Lcom/facebook/widget/PickerFragment$PickerFragmentAdapter;-><init>(Lcom/facebook/widget/PickerFragment;Landroid/content/Context;)V
     *     return-void
     * .end method
     * </source>
     *
     * while the decompiled class file looks as follows:
     * <source>
     * PlacePickerFragment$1(PlacePickerFragment paramPlacePickerFragment, Context x0) {
     *     super(paramPlacePickerFragment, x0);
     * }
     * </source>
     *
     * @param m   the {@link IMethod} to normalize
     * @return  null if this normalization does not apply, otherwise the normalized fuzzy descriptor {@see getFuzzyDescriptor}
     */
    private static String normalizeAnonymousInnerClassConstructor(IMethod m) {
        if (WalaUtils.isAnonymousInnerInnerClass(m.getDeclaringClass()) && m.isInit() && m.getNumberOfParameters() > 1) {
            // this can be anything -> normalize constructor to (X)V
            logger.trace("[normalizeAnonymousInnerClassConstructor] found anonymous inner inner class constructor: "+ m.getSignature());
            return "(X)V";
        }

        // check if we have an anonymous inner class constructor with a sufficient number of arguments
        if (WalaUtils.isAnonymousInnerClass(m.getDeclaringClass()) && m.isInit() && m.getNumberOfParameters() > 2) {
            logger.trace("[normalizeAnonymousInnerClassConstructor] method: " + m.getSignature());
            logger.trace(Utils.INDENT + "descriptor: " + m.getDescriptor() + "  # params: " + m.getNumberOfParameters());

            String enclosingClazzName = WalaUtils.simpleName(m.getDeclaringClass());
            enclosingClazzName = enclosingClazzName.substring(0, enclosingClazzName.lastIndexOf('$'));

            // check if both argument types are custom types
            for (int i : new Integer[]{1, 2}) {
                if (m.getParameterType(i).getClassLoader().equals(ClassLoaderReference.Application)) {
                    IClass ct = m.getClassHierarchy().lookupClass(m.getParameterType(1));
                    boolean isAppClazz = ct == null || WalaUtils.isAppClass(ct);
                    if (!isAppClazz)
                        return null;
                } else
                    return null;
            }

            IClass superClazz = null;
            try {
                IClass ic = WalaUtils.lookupClass(m.getClassHierarchy(), enclosingClazzName);
                superClazz = ic.getSuperclass();
            } catch (ClassNotFoundException e) {
                // class lookup can also fail for lambdas, e.g. if superclass is kotlin.jvm.internal.Lambda
                // we then default to fuzzy descriptor
                logger.trace("Could not lookup " + enclosingClazzName + "  in bytecode normalization");
                return null;
            }

            String argType1 = Utils.convertToFullClassName(m.getParameterType(1).getName().toString());
            String argType2 = Utils.convertToFullClassName(m.getParameterType(2).getName().toString());

            // now check whether this normalization needs to be applied
            if (argType1.equals(enclosingClazzName) &&
                    argType2.equals(WalaUtils.simpleName(superClazz))) {

                StringBuilder sb = new StringBuilder("(");

                // param0 is the object (for non-static calls), param1 the first arg to be skipped (doesn't matter
                // if whether we skip param1 or param2 since both are replaced by placeholder value)
                for (int i = 2; i < m.getNumberOfParameters(); i++) {

                    if (m.getParameterType(i).getClassLoader().equals(ClassLoaderReference.Application)) {
                        IClass ct = m.getClassHierarchy().lookupClass(m.getParameterType(i));
                        boolean isAppClazz = ct == null || WalaUtils.isAppClass(ct);
                        sb.append(isAppClazz ? customTypeReplacement : m.getParameterType(i).getName().toString());
                    } else
                        sb.append(m.getParameterType(i).getName().toString());
                }
                sb.append(")V");

                logger.trace(Utils.INDENT + "> bytecode normalization applied to " + m.getSignature() + "  fuzzy desc: " + sb.toString());
                return sb.toString();
            }
        }
        return null;
    }


    private static final String customTypeReplacement = "X";

    /**
     * A {@link Descriptor} only describes input arg types + return type, e.g.
     * The Descriptor of AdVideoView.onError(Landroid/media/MediaPlayer;II)Z  is (Landroid/media/MediaPlayerII)Z
     * In order to produce a fuzzy (robust against identifier-renaming) descriptor we replace each custom type by a fixed
     * replacement, e.g. we receive a descriptor like (XII)Z
     * Note: library dependencies, i.e. lib A depends on lib B are not a problem. If we analyze lib A without loading lib B,
     * any type of lib B will be loaded with the Application classloader but will _not_ be in the classhierarchy.
     * @param m  {@link IMethod}
     * @return a fuzzy descriptor
     */
    private static String getFuzzyDescriptor(IMethod m) {
        logger.trace("[getFuzzyDescriptor]");
        logger.trace("-  signature: " + m.getSignature());
        logger.trace("- descriptor: " + m.getDescriptor().toString());

        StringBuilder sb = new StringBuilder("(");

        for (int i = (m.isStatic()? 0 : 1) ; i < m.getNumberOfParameters(); i++) {
            boolean isAppClazz = false;

            if (m.getParameterType(i).getClassLoader().equals(ClassLoaderReference.Application)) {
                IClass ct = m.getClassHierarchy().lookupClass(m.getParameterType(i));
                isAppClazz = ct == null || WalaUtils.isAppClass(ct);
                sb.append(isAppClazz? customTypeReplacement : m.getParameterType(i).getName().toString());
            } else
                sb.append(m.getParameterType(i).getName().toString());

            //logger.trace(LogConfig.INDENT + "- param ref: " + m.getParameterType(i).getName().toString() + (isAppClazz? "  -> " + customTypeReplacement : ""));
        }
        //logger.trace("");
        sb.append(")");
        if (m.getReturnType().getClassLoader().equals(ClassLoaderReference.Application)) {
            IClass ct = m.getClassHierarchy().lookupClass(m.getReturnType());
            sb.append(ct == null || WalaUtils.isAppClass(ct)? customTypeReplacement : m.getReturnType().getName().toString());
        } else
            sb.append(m.getReturnType().getName().toString());

        logger.trace("-> new type: " + sb.toString());
        return sb.toString();
    }
}
