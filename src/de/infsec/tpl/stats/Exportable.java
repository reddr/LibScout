package de.infsec.tpl.stats;

/**
 * Classes that implement this interface
 * need to return a custom object with class data
 * that is serializable/exportable via json.
 *
 * For this purpose, we create in these classes
 * an inner class Export that is returned by export()
 */
public interface Exportable {
    Object export();
}
