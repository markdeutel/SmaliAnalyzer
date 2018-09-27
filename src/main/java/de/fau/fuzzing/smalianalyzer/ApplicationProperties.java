package de.fau.fuzzing.smalianalyzer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Properties;

public class ApplicationProperties
{
    private static final Logger LOG = LogManager.getLogger();
    private static final String PROPERTIES_PATH = "application.properties";

    private String aaptPath = null;

    private static ApplicationProperties instance;

    private ApplicationProperties()
    {
        try
        {
            final Properties properties = new Properties();
            properties.load(ClassLoader.getSystemClassLoader().getResourceAsStream(PROPERTIES_PATH));
            aaptPath = properties.getProperty("android.sdk.aapt.path", "");
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

    public String getAAPTPath()
    {
        return aaptPath;
    }
}
