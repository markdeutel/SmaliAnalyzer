package de.fau.fuzzing.smalianalyzer.parse;

public class SmaliHeader
{
    private String className = null;
    private String superName = null;

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
}
