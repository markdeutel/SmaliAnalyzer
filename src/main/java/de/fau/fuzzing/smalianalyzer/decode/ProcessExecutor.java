package de.fau.fuzzing.smalianalyzer.decode;

import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;

public class ProcessExecutor
{
    private static final Logger LOG = LogManager.getLogger(ProcessExecutor.class.getName());
    private static final String AAPT2_PATH_LINUX = "aapt2";
    private static final String AAPT2_PATH_WINDOWS = "aapt2.exe";
    private static final String PTHREAD_PATH_WINDOWS = "libwinpthread-1.dll";
    private static final Path AAPT2_LOCAL_PATH_LINUX = Paths.get("./aapt2");
    private static final Path AAPT2_LOCAL_PATH_WINDOWS = Paths.get("./aapt2");
    private static final Path PTHREAD_LOCAL_PATH_WINDOWS = Paths.get("./libwinpthread-1.dll");

    private enum OSType
    {
        WINDOWS, LINUX, MACOS, GENERIC
    }

    public static InputStream executeAAPT2(final String apkFilePath) throws IOException
    {
        final OSType type = getOSType();
        LOG.debug("OS type: {}", type);
        switch (type)
        {
            case LINUX:
                return executeAAPT2Linux(apkFilePath);
            case WINDOWS:
            case MACOS:
            case GENERIC:
            default:
                throw new UnsupportedOperationException("At the moment the only supported operating system is Linux.");
        }
    }

    private static InputStream executeAAPT2Linux(final String apkFilePath) throws IOException
    {
        if (!Files.exists(AAPT2_LOCAL_PATH_LINUX))
        {
            try(final InputStream stream = ClassLoader.getSystemClassLoader().getResourceAsStream(AAPT2_PATH_LINUX))
            {
                Files.copy(stream, AAPT2_LOCAL_PATH_LINUX, StandardCopyOption.REPLACE_EXISTING);
                final Set<PosixFilePermission> permissions = Sets.newHashSet();
                permissions.add(PosixFilePermission.OWNER_EXECUTE);
                Files.setPosixFilePermissions(AAPT2_LOCAL_PATH_LINUX, permissions);
            }
        }

        final String[] cmd = {AAPT2_LOCAL_PATH_LINUX.toString(), "dump", "xmltree", apkFilePath, "--file", "AndroidManifest.xml"};
        LOG.info("Executing AAPT2 using command: {}", Arrays.toString(cmd));
        return exec(cmd).getInputStream();
    }

    private static InputStream executeAAPT2Windows(final String apkFilePath) throws IOException
    {
        if (!Files.exists(AAPT2_LOCAL_PATH_WINDOWS))
        {
            try(final InputStream stream = ClassLoader.getSystemClassLoader().getResourceAsStream(AAPT2_PATH_WINDOWS))
            {
                Files.copy(stream, AAPT2_LOCAL_PATH_WINDOWS, StandardCopyOption.REPLACE_EXISTING);
            }
            try(final InputStream stream = ClassLoader.getSystemClassLoader().getResourceAsStream(PTHREAD_PATH_WINDOWS))
            {
                Files.copy(stream, PTHREAD_LOCAL_PATH_WINDOWS, StandardCopyOption.REPLACE_EXISTING);
            }
        }

        final String[] cmd = {AAPT2_LOCAL_PATH_WINDOWS.toString(), "dump", "xmltree", apkFilePath, "--file", "AndroidManifest.xml"};
        LOG.info("Executing AAPT2 using command: {}", Arrays.toString(cmd));
        return exec(cmd).getInputStream();
    }

    private static OSType getOSType()
    {
        final String os = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
        if (os.contains("mac") || os.contains("darwin"))
            return OSType.MACOS;
        else if (os.contains("win"))
            return OSType.WINDOWS;
        else if (os.contains("nux"))
            return OSType.LINUX;
        return OSType.GENERIC;
    }

    private static Process exec(final String... command) throws IOException
    {
        return new ProcessBuilder().command(command)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .redirectInput(ProcessBuilder.Redirect.INHERIT)
                .redirectOutput(ProcessBuilder.Redirect.PIPE).start();
    }
}
