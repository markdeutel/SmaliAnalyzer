package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.SetMultimap;
import de.fau.fuzzing.smalianalyzer.decode.ApkDecoder;
import de.fau.fuzzing.smalianalyzer.parse.SmaliFileVisitor;
import de.fau.fuzzing.smalianalyzer.parse.SmaliParser;
import de.fau.fuzzing.smalianalyzer.serialize.JsonWriter;
import org.apache.commons.cli.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Set;

public class SmaliAnalyzer
{
    private static final Logger LOG = LogManager.getLogger(SmaliAnalyzer.class.getName());

    private static final String DEFAULT_OUTPUT_PATH = "./";
    private static final String USAGE_STRING = "smalianalyzer [OPTIONS] <FILE>";

    public static void main(String[] args) throws ParseException
    {
        final Options options = new Options();
        options.addOption("h", "Print this dialog");
        options.addOption("o", true, "Specify the output folder.");

        final CommandLineParser parser = new DefaultParser();
        final CommandLine commandLine = parser.parse(options, args);

        Path outputPath = Paths.get(DEFAULT_OUTPUT_PATH);
        if (commandLine.hasOption("o"))
        {
            outputPath = Paths.get(commandLine.getOptionValue("o"));
        }
        else if (commandLine.hasOption("h"))
        {
            printHelp(options);
            return;
        }

        args = commandLine.getArgs();
        if (args.length >= 1)
        {
            final Path sourcePath = Paths.get(args[0]);
            if (Files.isDirectory(sourcePath))
            {
                decodeApks(sourcePath, outputPath);
            }
            else if (Files.isRegularFile(sourcePath))
            {
                decodeApk(sourcePath, outputPath);
            }
        }
        else
        {
            printHelp(options);
        }
    }

    private static void decodeApk(final Path sourcePath, final Path outputPath)
    {
        Path rootPath = Paths.get("./tmp");
        if (ApkDecoder.decode(sourcePath, rootPath))
        {
            final SetMultimap<String, String> actionsResult = ApkDecoder.decodeManifest(sourcePath);
            if (actionsResult != null)
                JsonWriter.writeToFile(outputPath.resolve(sourcePath.getFileName().toString().replaceAll(".apk", ".meta")), actionsResult.asMap());

            final Set<String> components = SmaliFileVisitor.searchFileTreeForComponents(rootPath);
            if (components != null)
            {
                final SmaliFileVisitor.InvocationCallers invocationCallers =
                        SmaliFileVisitor.searchFileTreeForInvocationCallers(rootPath, components);
                if (invocationCallers != null)
                {
                    final Map<String, SmaliParser.Component> result = SmaliParser.parseComponents(rootPath, components, invocationCallers);
                    if (result != null)
                        JsonWriter.writeToFile(outputPath.resolve(sourcePath.getFileName().toString().replaceAll(".apk", ".json")), result);
                }
            }

            // cleanup before exiting
            ApkDecoder.deleteTemporaryFiles(rootPath);
        }
    }

    private static void decodeApks(final Path sourcePath, final Path outputPath)
    {
        try (final DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath, "*.apk"))
        {
            for (final Path apkFile : directoryStream)
            {
                decodeApk(apkFile, outputPath);
            }
        }
        catch (IOException e)
        {
            LOG.error("Failed parsing directory: " + sourcePath.toString(), e);
        }
    }

    private static void printHelp(final Options options)
    {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp(USAGE_STRING, options);
    }
}
