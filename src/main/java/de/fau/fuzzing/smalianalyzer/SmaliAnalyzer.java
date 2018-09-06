package de.fau.fuzzing.smalianalyzer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import de.fau.fuzzing.smalianalyzer.decode.ApkDecoder;
import de.fau.fuzzing.smalianalyzer.parser.SmaliFileVisitor;
import de.fau.fuzzing.smalianalyzer.parser.SmaliParser;
import org.apache.commons.cli.*;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class SmaliAnalyzer
{
    private static final Logger LOG = LogManager.getLogger(SmaliAnalyzer.class.getName());

    private static final String DEFAULT_OUTPUT_PATH = "./output.json";
    private static final String USAGE_STRING = "smalianalyzer [OPTIONS] <FILE>";

    public static void main(String[] args) throws IOException, ParseException
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
            Path sourcePath = Paths.get(args[0]);
            Path rootPath = Paths.get("./tmp");
            if (ApkDecoder.decode(sourcePath, rootPath))
            {
                final Set<String> components = SmaliFileVisitor.searchFileTreeForComponents(rootPath);
                if (components != null)
                {
                    final SmaliFileVisitor.InvocationCallers invocationCallers = SmaliFileVisitor.searchFileTreeForInvocationCallers(rootPath, components);
                    if (invocationCallers != null)
                    {

                        LOG.info("Parsing component classes");
                        final Map<String, Map<String, Collection<String>>> result = new HashMap<>();
                        for (final String componentClass : components)
                        {
                            try
                            {
                                final SmaliParser.Component component = SmaliParser.parseComponent(
                                        getComponentPath(rootPath, componentClass), invocationCallers);
                                if (!component.invocations.isEmpty())
                                    result.put(component.className, component.invocations.asMap());
                            }
                            catch (Exception e)
                            {
                                LOG.error(e);
                            }
                        }

                        LOG.info("Writing result to file: {}", outputPath.toString());
                        writeToJsonFile(outputPath, result);
                    }
                }

                // cleanup before exiting
                LOG.info("Deleting temporary files");
                FileUtils.deleteDirectory(rootPath.toFile());
            }
        }
        else
        {
            printHelp(options);
        }
    }

    private static void printHelp(final Options options)
    {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp(USAGE_STRING, options);
    }

    private static Path getComponentPath(final Path rootPath, final String componentClass)
    {
        return rootPath.resolve(componentClass.substring(1, componentClass.length() - 1).concat(".smali"));
    }

    private static void writeToJsonFile(final Path outputPath, final Map<String, Map<String, Collection<String>>> result) throws IOException
    {
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))
        {
            // Build json serializer and write result to file
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            writer.write(gson.toJson(result));
        }
    }
}
