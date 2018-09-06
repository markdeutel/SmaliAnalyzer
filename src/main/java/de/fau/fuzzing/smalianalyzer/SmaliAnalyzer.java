package de.fau.fuzzing.smalianalyzer;

import de.fau.fuzzing.smalianalyzer.decode.ApkDecoder;
import de.fau.fuzzing.smalianalyzer.parse.SmaliFileVisitor;
import de.fau.fuzzing.smalianalyzer.parse.SmaliParser;
import de.fau.fuzzing.smalianalyzer.serialize.JsonWriter;
import org.apache.commons.cli.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class SmaliAnalyzer
{
    private static final Logger LOG = LogManager.getLogger(SmaliAnalyzer.class.getName());

    private static final String DEFAULT_OUTPUT_PATH = "./output.json";
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
                        final Map<String, SmaliParser.Component> result = new HashMap<>();
                        for (final String componentClass : components)
                        {
                            try
                            {
                                final SmaliParser.Component component = SmaliParser.parseComponent(
                                        getComponentPath(rootPath, componentClass), invocationCallers);
                                if (!component.getIntentInvocations().isEmpty() || !component.getBundleInvocations().isEmpty())
                                    result.put(component.getClassName(), component);
                            }
                            catch (Exception e)
                            {
                                LOG.error(e);
                            }
                        }

                        LOG.info("Writing result to file: {}", outputPath.toString());
                        JsonWriter.writeToFile(outputPath, result);
                    }
                }

                // cleanup before exiting
                ApkDecoder.deleteTemporaryFiles(rootPath);
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
}
