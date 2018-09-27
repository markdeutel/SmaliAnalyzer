package de.fau.fuzzing.smalianalyzer.decode;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Maps;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;
import de.fau.fuzzing.smalianalyzer.ApplicationProperties;
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
import java.io.InputStreamReader;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.Map;
import java.util.Set;

/**
 * @author Mark Deutel
 */
public class ApkDecoder
{
    private static final Logger LOG = LogManager.getLogger(ApkDecoder.class.getName());

    public static class IntentFilter
    {
        private Set<String> actions = Sets.newHashSet();
        private Set<String> categories = Sets.newHashSet();
        private Set<String> data = Sets.newHashSet();

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

    public static boolean decode(final Path apkFilePath, final Path outputFilePath)
    {
        try
        {
            final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.apk");
            if (!fileMatcher.matches(apkFilePath))
                return false;

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
            ZipDexContainer dexContainer = (ZipDexContainer) DexFileFactory.loadDexContainer(apkFilePath.toFile(), Opcodes.getDefault());
            for (final String entryName : dexContainer.getDexEntryNames())
            {
                LOG.info("Found .dex entry: {}", entryName);
                final DexBackedDexFile dexFile = DexFileFactory.loadDexEntry(apkFilePath.toFile(), entryName, true, Opcodes.getDefault());
                if (dexFile.isOdexFile())
                {
                    LOG.error("Can not disassemble .odex file without deodexing it.");
                    return false;
                }

                Baksmali.disassembleDexFile(dexFile, outputFilePath.toFile(), jobs, options);
            }

            return true;
        }
        catch (Exception e)
        {
            LOG.error("Failed decoding apk file:", e);
            return false;
        }
    }

    public static Map<String, IntentFilter> decodeManifest(final Path apkFilePath)
    {
        try
        {
            LOG.info("Decoding AndroidManifest.xml file");

            final Map<String, IntentFilter> result = Maps.newHashMap();
            final String[] cmd = {ApplicationProperties.getInstance().getAAPTPath(), "d", "xmltree", apkFilePath.toString(), "AndroidManifest.xml"};
            final Process process = Runtime.getRuntime().exec(cmd);
            try (final BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream())))
            {
                try (final BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream())))
                {
                    boolean dataTag = false;
                    String line, componentName = "";
                    SetMultimap<String, String> dataMap = null;
                    String scheme = "%s", host = "%s", port = "%s", path = "%s", pathPrefix = null, pathPattern = null;
                    while ((line = inputReader.readLine()) != null)
                    {
                        line = line.trim();

                        // read data tag
                        if (dataTag)
                        {
                            if (line.startsWith("A: android:scheme"))
                            {
                                scheme = unpackLine(line, scheme);
                                continue;
                            }
                            else if (line.startsWith("android:host"))
                            {
                                host = unpackLine(line, host);
                                continue;
                            }
                            else if (line.startsWith("A: android:port"))
                            {
                                port = unpackLine(line, port);
                                continue;
                            }
                            else if (line.startsWith("A: android:path"))
                            {
                                path = unpackLine(line, path);
                                continue;
                            }
                            else if (line.startsWith("A: android:pathPrefix"))
                            {
                                pathPrefix = unpackLine(line, pathPrefix);
                                continue;
                            }
                            else if (line.startsWith("A: android:pathPattern"))
                            {
                                pathPattern = unpackLine(line, pathPattern);
                                continue;
                            }

                            // <scheme>://<host>:<port>[<path>|<pathPrefix>|<pathPattern>]
                            final StringBuilder sb = new StringBuilder();
                            sb.append(scheme).append("://").append(host).append(":").append(port).append(path);
                            if (pathPrefix != null || pathPattern != null)
                            {
                                if (pathPrefix == null)
                                    sb.append(pathPrefix);
                                else
                                    sb.append(pathPattern);
                            }

                            final String dataString = sb.toString().replaceAll("\\.", "").replaceAll("\\*", "%s");
                            dataMap.put("data", dataString);
                            dataTag = false;
                        }

                        // read all other tags
                        if (line.startsWith("E: activity") || line.startsWith("E: service") || line.startsWith("E: receiver"))
                        {
                            if (dataMap != null)
                            {
                                final IntentFilter intentFilter = new IntentFilter();
                                intentFilter.actions.addAll(dataMap.get("actions"));
                                intentFilter.categories.addAll(dataMap.get("categories"));
                                intentFilter.data.addAll(dataMap.get("data"));
                                if (intentFilter.actions.size() > 0 || intentFilter.categories.size() > 0 ||
                                        intentFilter.data.size() > 0)
                                    result.put(componentName, intentFilter);
                            }

                            dataMap = HashMultimap.create();
                            while ((line = inputReader.readLine()) != null)
                            {
                                line = line.trim();
                                if (line.startsWith("A: android:name"))
                                {
                                    componentName = line.substring(line.indexOf('"') + 1);
                                    componentName = componentName.substring(0, componentName.indexOf('"'));
                                    break;
                                }
                            }
                        }
                        else if (line.startsWith("E: action"))
                        {
                            dataMap.put("actions", unpackLine(inputReader.readLine()));
                        }
                        else if (line.startsWith("E: category"))
                        {
                            dataMap.put("categories", unpackLine(inputReader.readLine()));
                        }
                        else if (line.startsWith("E: data"))
                        {
                            dataTag = true;
                        }
                    }

                    while ((line = errorReader.readLine()) != null)
                    {
                        LOG.error(line);
                    }

                    return result;
                }
            }
        }
        catch (IOException e)
        {
            LOG.error("Failed decoding manifest file:", e);
            return null;
        }
    }

    private static String unpackLine(final String line)
    {
        return unpackLine(line, "");
    }

    private static String unpackLine(final String line, final String fallback)
    {
        try
        {
            String result = line.substring(line.indexOf('"') + 1);
            return result.substring(0, result.indexOf('"'));
        }
        catch (Exception e)
        {
            return fallback;
        }
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
