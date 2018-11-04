package de.fau.fuzzing.smalianalyzer.serialize;

import com.google.common.collect.SetMultimap;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import de.fau.fuzzing.smalianalyzer.ApplicationProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;

/**
 * @author Mark Deutel
 */
public class OutputWriter
{
    private static final Logger LOG = LogManager.getLogger(OutputWriter.class.getName());

    public static void writeToJSONFile(final Path outputPath, final Object data) throws IOException
    {
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))
        {
            LOG.info("Writing result to json file: {}", outputPath.toString());
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
                    .registerTypeAdapter(SetMultimap.class, new JsonSetMultimapSerializer()).create();
            writer.write(gson.toJson(data));
        }
    }

    public static void writeToStringFile(final Path outputPath, final Set<String> stringSet) throws IOException
    {
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))
        {
            LOG.info("Writing result to string file: {}", outputPath.toString());
            for (final String str : stringSet)
            {
                writer.write(str);
                writer.newLine();
            }

            LOG.info("Fuzzing string results");
            final String[] cmd = {ApplicationProperties.getInstance().getRadamsaPath(), "-o", outputPath.toString(), "-r", outputPath.toString()};
            final Process process = Runtime.getRuntime().exec(cmd);
            try (final BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream())))
            {
                String line;
                while((line = errorReader.readLine()) != null)
                    System.err.println(line);
            }
        }
    }
}
