package de.fau.fuzzing.smalianalyzer.decode;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.ZipDexContainer;

import java.io.IOException;
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
