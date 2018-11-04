package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Maps;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;
import de.fau.fuzzing.smalianalyzer.decode.ApkDecoder;
import de.fau.fuzzing.smalianalyzer.parse.SmaliFileParser;
import de.fau.fuzzing.smalianalyzer.parse.SmaliProjectIndexer;
import de.fau.fuzzing.smalianalyzer.serialize.JsonWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.*;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class SmaliAnalyzer
{
    private static final Logger LOG = LogManager.getLogger();

    private static class ParsingResult
    {
        private ParsingResult(Map<String, Collection<String>> intentInvocations, Map<String, Collection<String>> bundleInvocations)
        {
            this.intentInvocations = intentInvocations;
            this.bundleInvocations = bundleInvocations;
        }

        Map<String, Collection<String>> intentInvocations;
        Map<String, Collection<String>> bundleInvocations;
    }

    public static void main(final String[] args)
    {
        if (args.length < 2)
        {
            System.out.println("Use like this: SmaliAnalyzer <SOURCE FILE/FOLDER> <OUTPUT FILE/FOLDER>");
            return;
        }

        long startTime = System.currentTimeMillis();

        final Path sourcePath = Paths.get(args[0]);
        final Path outputPath = Paths.get(args[1]);
        if (Files.isRegularFile(sourcePath, LinkOption.NOFOLLOW_LINKS))
        {
            analyzeApk(sourcePath, outputPath);
        }
        else if (Files.isDirectory(sourcePath, LinkOption.NOFOLLOW_LINKS))
        {
            analyzeApkFolder(sourcePath, outputPath);
        }
        else
        {
            System.out.println("source and output path have to be either both files or directories");
        }

        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Finished successful after " + TimeUnit.MILLISECONDS.toSeconds(elapsedTime) + " seconds");
    }

    private static void analyzeApkFolder(final Path sourcePath, final Path outputPath)
    {
        try (final DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath, "*.apk"))
        {
            for (final Path apkFile : directoryStream)
            {
                final Path outputFilePath = outputPath.resolve(apkFile.getFileName().toString().replaceAll(".apk", ".json"));
                analyzeApk(apkFile, outputFilePath);
            }
        }
        catch (IOException e)
        {
            LOG.error("Failed parsing directory: " + sourcePath.toString());
            LOG.error(e);
        }
    }

    private static void analyzeApk(final Path sourcePath, final Path outputPath)
    {
        final Path rootPath = Paths.get(sourcePath.toString().replaceAll(".apk", "/"));
        System.out.println(String.format("Decoding apk file: %s", sourcePath.toString()));
        if (ApkDecoder.decode(sourcePath, rootPath))
        {
            try
            {
                if (Files.notExists(outputPath.getParent(), LinkOption.NOFOLLOW_LINKS))
                    Files.createDirectories(outputPath.getParent());

                System.out.println("Parsing application manifest");
                final Map<String, ApkDecoder.IntentFilters> manifestResult = ApkDecoder.decodeManifest(sourcePath);
                if (manifestResult != null)
                    JsonWriter.writeToFile(Paths.get(outputPath.toString().replaceAll(".json", ".meta")), manifestResult);

                System.out.println("Indexing smali code");
                final SmaliProjectIndexer indexer = new SmaliProjectIndexer(rootPath);
                indexer.indexProject();

                int count = 0;
                long numInvocations = 0;
                System.out.println("Parsing found components");
                final Map<String, ParsingResult> result = Maps.newHashMap();
                for (final Path filePath : indexer.getComponentList())
                {
                    System.out.print(buildProgressBar(count, indexer.getComponentList().size(), 60));
                    final String componentName = getComponentName(rootPath, filePath);
                    final SetMultimap<String, String> intentResults = HashMultimap.create();
                    final SetMultimap<String, String> bundleResults = HashMultimap.create();
                    final Set<String> stringSet = Sets.newHashSet();
                    for (final String methodName : Constants.COMPONENT_ENTRY_METHODS)
                    {
                        final Map<String, String> registerMap = Maps.newHashMap();
                        SmaliFileParser.parseMethod(filePath, methodName, indexer.getIndexMap(), registerMap, intentResults, bundleResults, stringSet, 0);
                    }

                    numInvocations += intentResults.values().size();
                    numInvocations += bundleResults.values().size();

                    if (!intentResults.isEmpty() || !bundleResults.isEmpty())
                        result.put(componentName, new ParsingResult(intentResults.asMap(), bundleResults.asMap()));

                    count++;
                }

                System.out.print(clearProgressBar(60));
                System.out.println(String.format("Writing result to file: %s", outputPath.toString()));
                JsonWriter.writeToFile(outputPath, result);
                System.out.println("Tracked " + numInvocations + " invocations");

            }
            catch (Exception e)
            {
                LOG.error("Failed analyzing apk file: {}", sourcePath.toString());
                LOG.error(e);
            }
            finally
            {
                ApkDecoder.deleteTemporaryFiles(rootPath);
            }
        }
    }

    private static String getComponentName(final Path rootPath, final Path filePath)
    {
        String relPathStr = rootPath.toAbsolutePath().relativize(filePath.toAbsolutePath()).toString();
        return relPathStr.replaceAll("/", ".").replaceAll(".smali", "");
    }

    private static String buildProgressBar(int curr, int max, int len)
    {
        float step = (float) len / max;
        int prog = Math.round(curr * step);

        final StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < prog - 1; ++i)
            sb.append("=");
        sb.append(">");
        for (int i = prog; i < len; ++i)
            sb.append(" ");
        sb.append("] ").append(curr).append("/").append(max).append("\r");

        return sb.toString();
    }

    private static String clearProgressBar(int len)
    {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len + 20; ++i)
            sb.append(" ");
        return sb.append("\r").toString();
    }
}
