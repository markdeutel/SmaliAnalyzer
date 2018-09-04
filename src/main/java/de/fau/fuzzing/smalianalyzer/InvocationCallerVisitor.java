package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;

public class InvocationCallerVisitor extends SimpleFileVisitor<Path>
{
    private static final Logger LOG = LogManager.getLogger(InvocationCallerVisitor.class.getName());

    private Set<String> invocationCallers = Sets.newHashSet(SmaliParser.INTENT_CLASS);
    private Set<String> components;

    private InvocationCallerVisitor(final Set<String> components)
    {
        this.components = components;
    }

    static Set<String> searchFileTree(final Path rootPath, final Set<String> components) throws IOException
    {
        final InvocationCallerVisitor fileVisitor = new InvocationCallerVisitor(components);
        Files.walkFileTree(rootPath, fileVisitor);
        return fileVisitor.invocationCallers;
    }

    @Override
    public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException
    {
        final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.smali");
        if (fileMatcher.matches(path))
        {
            final SmaliParser.ClassHeader header = SmaliParser.peekHeader(path);
            if (!components.contains(header.name))
            {
                final SmaliParser.Class klass = SmaliParser.parse(path);
                for (final SmaliParser.Method method : klass.methods.values())
                {
                    if (!method.intentMethods.isEmpty())
                    {
                        invocationCallers.add(header.name);
                    }
                }
            }
        }

        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path path, IOException e)
    {
        LOG.error("Failed visiting file: {}", e);
        return FileVisitResult.CONTINUE;
    }
}
