package de.fau.fuzzing.smalianalyzer.decode;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.ZipDexContainer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Mark Deutel
 */
public class ApkDecoder
{
    private static final Logger LOG = LogManager.getLogger(ApkDecoder.class.getName());

    public static class IntentFilters
    {
        private Set<String> actions = Sets.newHashSet();
        private Set<String> categories = Sets.newHashSet();
        private Set<String> data = Sets.newHashSet();

        public boolean isEmpty()
        {
            return actions.isEmpty() && categories.isEmpty() && data.isEmpty();
        }

        public Set<String> getActions()
        {
            return actions;
        }

        public Set<String> getCategories()
        {
            return categories;
        }

        public Set<String> getData()
        {
            return data;
        }
    }

    public static void decode(final Path apkFilePath, final Path outputFilePath) throws IOException
    {
        final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.apk");
        if (!fileMatcher.matches(apkFilePath))
            throw new IllegalArgumentException(String.format("Specified file is not an APK file %s", apkFilePath.toString()));

        LOG.info("Decoding .apk file: {}", apkFilePath.toString());

        // set baksmali options
        final BaksmaliOptions options = new BaksmaliOptions();
        options.deodex = false;
        options.implicitReferences = false;
        options.parameterRegisters = true;
        options.localsDirective = true;
        options.sequentialLabels = true;
        options.debugInfo = false;
        options.codeOffsets = false;
        options.accessorComments = false;
        options.registerInfo = 0;
        options.inlineResolver = null;

        // query the number of available processors
        int jobs = Runtime.getRuntime().availableProcessors();

        // decode the dex file
        final ZipDexContainer dexContainer = (ZipDexContainer) DexFileFactory.loadDexContainer(apkFilePath.toFile(), Opcodes.getDefault());
        for (final String entryName : dexContainer.getDexEntryNames())
        {
            LOG.info("Found .dex entry: {}", entryName);
            final DexBackedDexFile dexFile = DexFileFactory.loadDexEntry(apkFilePath.toFile(), entryName, true, Opcodes.getDefault());
            if (dexFile.isOdexFile())
                throw new IllegalStateException("Can not disassemble .odex file without deodexing it.");

            Baksmali.disassembleDexFile(dexFile, outputFilePath.toFile(), jobs, options);
        }
    }

    public static Map<String, IntentFilters> decodeManifest(final Path apkFilePath) throws IOException, URISyntaxException
    {
        LOG.info("Decoding AndroidManifest.xml file");
        final Map<String, IntentFilters> result = Maps.newHashMap();
        final InputStream stream = ProcessExecutor.executeAAPT2(apkFilePath.toString());
        try (final BufferedReader inputReader = new BufferedReader(new InputStreamReader(stream)))
        {
            IntentFilters filters = null;
            String line, componentName = "";
            boolean dataMode = false;
            while ((line = inputReader.readLine()) != null)
            {
                if (dataMode)
                {
                    List<String> names = Lists.newArrayList("android:scheme", "android:host",
                            "android:port", "android:path", "android:pathPrefix", "android:pathPattern");
                    Map<String, String> dataValues = Maps.newHashMap();
                    while ((line = inputReader.readLine()) != null)
                    {
                        line = line.trim();
                        if (!line.startsWith("A: "))
                            break;

                        final Matcher matcher = Pattern.compile("A: .*\\(.*\\)=.* \\(Raw: .*\\)").matcher(line);
                        if (matcher.find())
                        {
                            String name = line.substring(line.indexOf(' ') + 1, line.indexOf('('));
                            String value = line.substring(line.indexOf('"') + 1);
                            dataValues.put(name, value.substring(0, value.indexOf('"')));
                        }
                    }

                    final String dataString = buildDataURI(dataValues);
                    filters.data.add(dataString);
                    dataMode = false;
                }

                line = line.trim();
                String dataTag = getDataTag(line);
                switch (dataTag)
                {
                    case "activity":
                    case "service":
                    case "receiver":
                        if (filters != null && !filters.isEmpty())
                            result.put(componentName, filters);
                        filters = new IntentFilters();
                        componentName = getAttributeValue(inputReader, line, "android:name");
                        break;
                    case "action":
                        filters.actions.add(getAttributeValue(inputReader, line, "android:name"));
                        break;
                    case "category":
                        filters.categories.add(getAttributeValue(inputReader, line, "android:name"));
                        break;
                    case "data":
                        dataMode = true;
                        break;
                }
            }

            if (filters != null && !filters.isEmpty())
                result.put(componentName, filters);

            return result;
        }
    }

    private static String getDataTag(final String line)
    {
        final Matcher matcher = Pattern.compile("E: .* \\(line=\\d+\\)").matcher(line);
        if (matcher.find())
            return line.split(" ")[1];
        return "";
    }

    private static String getAttributeValue(final BufferedReader reader, String line, final String name) throws IOException
    {
        while ((line = reader.readLine()) != null)
        {
            line = line.trim();
            if (!line.startsWith("A: "))
                break;

            final Matcher matcher = Pattern.compile("A: http://schemas.android.com/apk/res/" + name + ".*=.* \\(Raw: .*\\)").matcher(line);
            if (matcher.find())
            {
                String value = line.substring(line.indexOf('"') + 1);
                return value.substring(0, value.indexOf('"'));
            }
        }
        return "";
    }

    private static String buildDataURI(final Map<String, String> values)
    {
        // <scheme>://<host>:<port>[<path>|<pathPrefix>|<pathPattern>]
        final StringBuilder sb = new StringBuilder();
        sb.append(values.getOrDefault("http://schemas.android.com/apk/res/android:scheme", "%s")).append("://")
                .append(values.getOrDefault(" http://schemas.android.com/apk/res/android:host", "%s"))
                .append(":").append(values.getOrDefault("http://schemas.android.com/apk/res/android:port", "%s"))
                .append(values.getOrDefault("http://schemas.android.com/apk/res/android:path", "%s"))
                .append(values.getOrDefault("http://schemas.android.com/apk/res/android:pathPrefix", ""))
                .append(values.getOrDefault("http://schemas.android.com/apk/res/android:pathPattern", ""));
        return sb.toString().replace(".*", "%s");
    }

    public static void deleteTemporaryFiles(final Path filePath)
    {
        try
        {
            LOG.info("Deleting temporary files");
            FileUtils.deleteDirectory(filePath.toFile());
        }
        catch (IOException e)
        {
            LOG.error("Failed deleting files:", e);
        }
    }
}
