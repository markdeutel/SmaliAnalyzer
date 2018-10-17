package de.fau.fuzzing.smalianalyzer.parse;

import java.util.ArrayList;
import java.util.List;

public class SmaliHeader
{
    private String className = null;
    private String superName = null;
    private List<String> implementedClasses = new ArrayList<>();

    public String getClassName()
    {
        return className;
    }

    public void setClassName(String className)
    {
        this.className = className;
    }

    public String getSuperName()
    {
        return superName;
    }

    public void setSuperName(String superName)
    {
        this.superName = superName;
    }

    public List<String> getImplementedClasses() {
        return implementedClasses;
    }

    public void addImplementedClass(final String implementedClass) {
        implementedClasses.add(implementedClass);
    }
}
