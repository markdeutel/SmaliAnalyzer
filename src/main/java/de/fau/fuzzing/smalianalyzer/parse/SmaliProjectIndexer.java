package de.fau.fuzzing.smalianalyzer.parse;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import de.fau.fuzzing.smalianalyzer.Constants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SmaliProjectIndexer
{
    private static final Logger LOG = LogManager.getLogger();

    private final Path projectRootPath;
    private final List<Path> componentList = Lists.newArrayList();
    private final List<Path> parcableList = Lists.newArrayList();
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
        componentList.clear();
        Files.walkFileTree(projectRootPath, new IndexerFileVisitor());
        findComponentClasses();
        findParcableClasses();
        LOG.info("Indexed {} smali files", indexMap.keySet().size());
        LOG.info("Identified {} component classes", componentList.size());
        LOG.info("Identified {} parcable classes", componentList.size());
    }

    private void findComponentClasses()
    {
        int lastSize;
        final Set<String> superClasses = Sets.newHashSet(Constants.ANDROID_COMPONENTS);
        do
        {
            lastSize = superClasses.size();
            for (final String className : indexMap.keySet())
            {
                final IndexEntry index = indexMap.get(className);
                if (superClasses.contains(index.getSuperClass()))
                {
                    superClasses.add(className);
                    componentList.add(index.getFilePath());
                }
            }
        }
        while (superClasses.size() != lastSize);
    }

    private void findParcableClasses()
    {
        for (final String className : indexMap.keySet())
        {
            final IndexEntry index = indexMap.get(className);
            if (index.getImplementedClasses().contains(Constants.PARCABLE_CLASS))
            {
                parcableList.add(index.getFilePath());
            }
        }
    }

    public List<Path> getComponentList()
    {
        return componentList;
    }

    public List<Path> getParcableList()
    {
        return parcableList;
    }

    public Map<String, IndexEntry> getIndexMap()
    {
        return indexMap;
    }
}
