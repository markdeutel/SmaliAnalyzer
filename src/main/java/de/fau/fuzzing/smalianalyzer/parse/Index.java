package de.fau.fuzzing.smalianalyzer.parse;

import java.nio.file.Path;

public class Index
{
    private Path filePath;
    private String superClass;

    public Index(Path filePath, String superClass)
    {
        this.filePath = filePath;
        this.superClass = superClass;
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
}
