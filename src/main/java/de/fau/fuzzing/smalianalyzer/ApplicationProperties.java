package de.fau.fuzzing.smalianalyzer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

public class ApplicationProperties
{
    private static final Logger LOG = LogManager.getLogger();
    private static final String PROPERTIES_PATH = "application.properties";

    private String radamsaPath = null;
    private int maxDepth = 0;

    private static ApplicationProperties instance;

    private ApplicationProperties()
    {
        try
        {
            final InputStream propertiesStream = ClassLoader.getSystemClassLoader().getResourceAsStream(PROPERTIES_PATH);
            final Properties properties = new Properties();
            properties.load(propertiesStream);
            radamsaPath = properties.getProperty("tools.radamsa.path", ".");
            maxDepth = Integer.parseInt(properties.getProperty("constants.max.depth", "0"));
        }
        catch (IOException e)
        {
            LOG.warn("Failed reading application properties:", e);
        }
    }

    public static ApplicationProperties getInstance()
    {
        if (ApplicationProperties.instance == null)
        {
            ApplicationProperties.instance = new ApplicationProperties();
        }
        return ApplicationProperties.instance;
    }

    public String getRadamsaPath() { return radamsaPath; }

    public int getMaxDepth()
    {
        return maxDepth;
    }
}
