package de.fau.fuzzing.smalianalyzer.serialize;

import com.google.common.collect.SetMultimap;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * @author Mark Deutel
 */
public class JsonWriter
{
    private static final Logger LOG = LogManager.getLogger(JsonWriter.class.getName());

    public static void writeToFile(final Path outputPath, final Object data)
    {
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))
        {
            LOG.info("Writing result to json file: {}", outputPath.toString());
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
                    .registerTypeAdapter(SetMultimap.class, new JsonSetMultimapSerializer()).create();
            writer.write(gson.toJson(data));
        }
        catch (IOException e)
        {
            LOG.error("Failed writing json file:", e);
        }
    }
}
