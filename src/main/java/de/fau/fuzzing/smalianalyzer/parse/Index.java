package de.fau.fuzzing.smalianalyzer.parse;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class Index
{
    private Path filePath;
    private String superClass;
    private List<String> implementedClasses = new ArrayList<>();

    public Index(Path filePath, SmaliHeader header)
    {
        this.filePath = filePath;
        this.superClass = header.getSuperName();
        this.implementedClasses = header.getImplementedClasses();
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

    public List<String> getImplementedClasses()
    {
        return implementedClasses;
    }

    public void setImplementedClasses(List<String> implementedClasses)
    {
        this.implementedClasses = implementedClasses;
    }
}
