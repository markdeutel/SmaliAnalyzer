package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Maps;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;
import de.fau.fuzzing.smalianalyzer.decode.ApkDecoder;
import de.fau.fuzzing.smalianalyzer.parse.SmaliFileParser;
import de.fau.fuzzing.smalianalyzer.parse.SmaliProjectIndexer;
import de.fau.fuzzing.smalianalyzer.serialize.OutputWriter;
import org.apache.commons.cli.*;
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

    public static void main(final String[] args) throws ParseException
    {
        final Options options = new Options();
        options.addOption("h", false, "print this dialog");
        options.addOption("f", true, "specify an input APK file or a folder containing APK files");
        options.addOption("o", true, "specify the output folder");

        final CommandLineParser parser = new DefaultParser();
        final CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("h") || args.length == 0)
        {
            HelpFormatter helpFormatter = new HelpFormatter();
            helpFormatter.printHelp("SmaliAnalyzer", options);
            return;
        }

        Path sourcePath = Paths.get(".");
        Path outputPath = Paths.get(".");
        if (cmd.hasOption("f"))
            sourcePath = Paths.get(cmd.getOptionValue("f"));
        if (cmd.hasOption("o"))
            outputPath = Paths.get(cmd.getOptionValue("o"));

        long startTime = System.currentTimeMillis();

        if(!Files.isDirectory(outputPath))
        {
            System.err.println("Output path has to be a directory");
            return;
        }

        if (Files.isRegularFile(sourcePath, LinkOption.NOFOLLOW_LINKS))
        {
            final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.apk");
            if (fileMatcher.matches(sourcePath))
                analyzeApk(sourcePath, outputPath);
        }
        else if (Files.isDirectory(sourcePath, LinkOption.NOFOLLOW_LINKS))
        {
            analyzeApkFolder(sourcePath, outputPath);
        }
        else
        {
            System.err.println("Source path has to be either a file or a directory");
            return;
        }

        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        System.out.println("Finished after " + TimeUnit.MILLISECONDS.toSeconds(elapsedTime) + " seconds");
    }

    private static void analyzeApkFolder(final Path sourcePath, final Path outputPath)
    {
        assert Files.isDirectory(outputPath);
        assert Files.isDirectory(sourcePath);

        try (final DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath, "*.apk"))
        {
            for (final Path apkFile : directoryStream)
            {
                analyzeApk(apkFile, outputPath);
            }
        }
        catch (IOException e)
        {
            System.err.println(String.format("Failed parsing directory: %s", sourcePath.toString()));
            e.printStackTrace();
            LOG.error(e);
        }
    }

    private static void analyzeApk(final Path sourcePath, final Path outputPath)
    {
        assert Files.isDirectory(outputPath);
        assert Files.isRegularFile(sourcePath);

        final Path rootPath = Paths.get(sourcePath.toString().replaceAll(".apk", "/"));
        try
        {
            System.out.println(String.format("Decoding apk file: %s", sourcePath.toString()));
            ApkDecoder.decode(sourcePath, rootPath);

            System.out.println("Parsing application manifest");
            final Map<String, ApkDecoder.IntentFilters> manifestResult = ApkDecoder.decodeManifest(sourcePath);

            System.out.println("Indexing smali code");
            final SmaliProjectIndexer indexer = new SmaliProjectIndexer(rootPath);
            indexer.indexProject();

            int count = 0;
            long numInvocations = 0;
            System.out.println("Parsing found components");
            final Map<String, ParsingResult> result = Maps.newHashMap();
            final Set<String> stringSet = Sets.newHashSet();
            for (final Path filePath : indexer.getComponentList())
            {
                System.out.print(buildProgressBar(count, indexer.getComponentList().size(), 60));
                final String componentName = getComponentName(rootPath, filePath);
                final SetMultimap<String, String> intentResults = HashMultimap.create();
                final SetMultimap<String, String> bundleResults = HashMultimap.create();
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
            System.out.println("Tracked " + numInvocations + " invocations");

            // write parsing results to file
            if (Files.notExists(outputPath.toAbsolutePath().getParent(), LinkOption.NOFOLLOW_LINKS))
                Files.createDirectories(outputPath);

            final Path jsonOutputPath = outputPath.resolve(sourcePath.getFileName().toString().replace(".apk", ".json"));
            System.out.println(String.format("Writing JSON results to file: %s", jsonOutputPath.toString()));
            OutputWriter.writeToJSONFile(jsonOutputPath, result);

            final Path metaOutputPath = outputPath.resolve(sourcePath.getFileName().toString().replace(".apk", ".meta"));
            System.out.println(String.format("Writing META results to file: %s", metaOutputPath.toString()));
            OutputWriter.writeToJSONFile(metaOutputPath, manifestResult);

            final Path stringOutputPath = outputPath.resolve(sourcePath.getFileName().toString().replace(".apk", ".str"));
            System.out.println(String.format("Writing STRING results to file: %s", stringOutputPath.toString()));
            OutputWriter.writeToStringFile(stringOutputPath, stringSet);
        }
        catch (Exception e)
        {
            System.err.println(String.format("Failed analyzing apk file: %s", sourcePath.toString()));
            e.printStackTrace();
            LOG.error(e);
        }
        finally
        {
            ApkDecoder.deleteTemporaryFiles(rootPath);
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
