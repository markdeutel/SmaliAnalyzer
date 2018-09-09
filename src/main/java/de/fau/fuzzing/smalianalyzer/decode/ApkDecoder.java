package de.fau.fuzzing.smalianalyzer.decode;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
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
import java.nio.file.Path;

/**
 * @author Mark Deutel
 */
public class ApkDecoder
{
    private static final Logger LOG = LogManager.getLogger(ApkDecoder.class.getName());

    public static boolean decode(final Path apkFilePath, final Path outputFilePath)
    {
        try
        {
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

    public static SetMultimap<String, String> decodeManifest(final Path apkFilePath)
    {
        try
        {
            LOG.info("Decoding AndroidManifest.xml file");

            final SetMultimap<String, String> actions = HashMultimap.create();
            final String[] cmd = {"./ext/aapt", "d", "xmltree", apkFilePath.toString(), "AndroidManifest.xml"};
            final Process process = Runtime.getRuntime().exec(cmd);
            try (final BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream())))
            {
                try (final BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream())))
                {
                    String line, componentName = "";
                    while ((line = inputReader.readLine()) != null)
                    {
                        line = line.trim();
                        if (line.startsWith("E: activity"))
                        {
                            while ((line = inputReader.readLine()) != null)
                            {
                                line = line.trim();
                                if (line.startsWith("A: android:name(0x01010003)"))
                                {
                                    componentName = line.substring(line.indexOf('"') + 1);
                                    componentName = componentName.substring(0, componentName.indexOf('"'));
                                    break;
                                }
                            }
                        }
                        else if (line.startsWith("E: action"))
                        {
                            String actionLine = inputReader.readLine();
                            actionLine = actionLine.substring(actionLine.indexOf('"') + 1);
                            actionLine = actionLine.substring(0, actionLine.indexOf('"'));
                            actions.put(componentName, actionLine);
                        }
                    }

                    while ((line = errorReader.readLine()) != null)
                    {
                        LOG.error(line);
                    }

                    return actions;
                }
            }
        }
        catch (IOException e)
        {
            LOG.error("Failed decoding manifest file:", e);
            return null;
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
