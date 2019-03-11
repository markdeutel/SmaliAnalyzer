package de.fau.fuzzing.smalianalyzer.parse;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class IndexEntry
{
    private Path filePath;
    private String superClass;
    private List<String> implementedInterfaces;

    public IndexEntry(Path filePath, SmaliHeader header)
    {
        this.filePath = filePath;
        this.superClass = header.getSuperName();
        this.implementedInterfaces = header.getImplementedClasses();
    }

    public Path getFilePath()
    {
        return filePath;
    }

    public void setFilePath(Path filePath)
    {
        this.filePath = filePath;
    }

    public String getSuperClass()
    {
        return superClass;
    }

    public void setSuperClass(String superClass)
    {
        this.superClass = superClass;
    }

    public List<String> getImplementedInterfaces()
    {
        return implementedInterfaces;
    }

    public void setImplementedInterfaces(List<String> implementedClasses)
    {
        this.implementedInterfaces = implementedClasses;
    }
}
