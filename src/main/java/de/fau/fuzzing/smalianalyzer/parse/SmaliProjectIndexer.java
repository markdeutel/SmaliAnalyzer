package de.fau.fuzzing.smalianalyzer.parse;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import de.fau.fuzzing.smalianalyzer.Constants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.Set;

public class SmaliProjectIndexer
{
    private static final Logger LOG = LogManager.getLogger();

    private final Path projectRootPath;
    private final Set<Path> componentSet = Sets.newHashSet();
    private final Set<Path> parcelableSet = Sets.newHashSet();
    private final Map<String, IndexEntry> indexMap = Maps.newHashMap();

    private class IndexerFileVisitor extends SimpleFileVisitor<Path>
    {
        @Override
        public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes)
        {
            final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.smali");
            if (fileMatcher.matches(path))
            {
                try
                {
                    final SmaliHeader header = SmaliFileParser.parseSmaliHeader(path);
                    indexMap.put(header.getClassName(), new IndexEntry(path, header));
                }
                catch (Exception e)
                {
                    LOG.error("Failed indexing file: {}", path.toString());
                    LOG.error(e);
                }
            }
            return FileVisitResult.CONTINUE;
        }
    }

    public SmaliProjectIndexer(final Path projectRootPath) throws IOException
    {
        this.projectRootPath = projectRootPath;
    }

    public void indexProject() throws IOException
    {
        LOG.info("Indexing smali project: {}", projectRootPath.toString());
        indexMap.clear();
        componentSet.clear();
        Files.walkFileTree(projectRootPath, new IndexerFileVisitor());
        findClassesBySuperClass(componentSet, Constants.ANDROID_COMPONENTS);
        findClassesByImplementedInterface(parcelableSet, Constants.ANDROID_PARCELABLE);
        LOG.info("Indexed {} smali files", indexMap.keySet().size());
        LOG.info("Identified {} component classes", componentSet.size());
        LOG.info("Identified {} parcelable classes", parcelableSet.size());
    }

    private void findClassesBySuperClass(final Set<Path> resultSet, final Set<String> superClasses)
    {
        int lastSize;
        final Set<String> superClassesCpy = Sets.newHashSet(superClasses);
        do
        {
            lastSize = superClassesCpy.size();
            for (final String className : indexMap.keySet())
            {
                final IndexEntry index = indexMap.get(className);
                if (superClassesCpy.contains(index.getSuperClass()))
                {
                    if (!superClassesCpy.contains(className))
                    {
                        resultSet.add(index.getFilePath());
                        superClassesCpy.add(className);
                    }
                }
            }
        }
        while (superClassesCpy.size() != lastSize);
    }

    private void findClassesByImplementedInterface(final Set<Path> resultSet, final Set<String> interfaces)
    {
        for (final String className : indexMap.keySet())
        {
            final IndexEntry index = indexMap.get(className);
            for (final String interfaceName : index.getImplementedInterfaces())
            {
                if (interfaces.contains(interfaceName))
                {
                    resultSet.add(index.getFilePath());
                }
            }
        }
    }

    public Set<Path> getComponentSet()
    {
        return componentSet;
    }

    public Set<Path> getParcelableSet()
    {
        return parcelableSet;
    }

    public Map<String, IndexEntry> getIndexMap()
    {
        return indexMap;
    }
}
