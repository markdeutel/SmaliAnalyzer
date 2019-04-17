package de.fau.fuzzing.smalianalyzer.decode;

import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.Closeable;
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

public class ProcessExecutor implements Closeable
{
    private static final Logger LOG = LogManager.getLogger(ProcessExecutor.class.getName());

    private static final String AAPT2_PATH_LINUX = "aapt2";
    private static final String AAPT2_PATH_WINDOWS = "aapt2.exe";
    private static final String PTHREAD_PATH_WINDOWS = "libwinpthread-1.dll";
    private static final Path AAPT2_LOCAL_PATH_LINUX = Paths.get("./aapt2");
    private static final Path AAPT2_LOCAL_PATH_WINDOWS = Paths.get("./aapt2");
    private static final Path PTHREAD_LOCAL_PATH_WINDOWS = Paths.get("./libwinpthread-1.dll");

    private InputStream processStream;

    private enum OSType
    {
        WINDOWS, LINUX, MACOS, GENERIC
    }

    public ProcessExecutor(final Path apkFilePath) throws IOException
    {
        final OSType type = getOSType();
        LOG.debug("OS type: {}", type);
        switch (type)
        {
            case LINUX:
                processStream = executeAAPT2Linux(apkFilePath.toString());
                break;
            case WINDOWS:
                processStream = executeAAPT2Windows(apkFilePath.toString());
                break;
            case MACOS:
            case GENERIC:
            default:
                throw new UnsupportedOperationException("At the moment the only supported operating systems are Windows and Linux.");
        }
    }

    @Override
    public void close() throws IOException
    {
        processStream.close();
        Files.deleteIfExists(AAPT2_LOCAL_PATH_LINUX);
        Files.deleteIfExists(AAPT2_LOCAL_PATH_WINDOWS);
        Files.deleteIfExists(PTHREAD_LOCAL_PATH_WINDOWS);
    }

    public InputStream getProcessStream()
    {
        return processStream;
    }

    private InputStream executeAAPT2Linux(final String apkFilePath) throws IOException
    {
        if (!Files.exists(AAPT2_LOCAL_PATH_LINUX))
            copyFile(AAPT2_PATH_LINUX, AAPT2_LOCAL_PATH_LINUX, OSType.LINUX);
        final String[] cmd = {AAPT2_LOCAL_PATH_LINUX.toString(), "dump", "xmltree", apkFilePath, "--file", "AndroidManifest.xml"};
        LOG.info("Executing AAPT2 using command: {}", Arrays.toString(cmd));
        return exec(cmd).getInputStream();
    }

    private InputStream executeAAPT2Windows(final String apkFilePath) throws IOException
    {
        if (!Files.exists(AAPT2_LOCAL_PATH_WINDOWS))
        {
            copyFile(AAPT2_PATH_WINDOWS, AAPT2_LOCAL_PATH_WINDOWS, OSType.WINDOWS);
            copyFile(PTHREAD_PATH_WINDOWS, PTHREAD_LOCAL_PATH_WINDOWS, OSType.WINDOWS);
        }
        final String[] cmd = {AAPT2_LOCAL_PATH_WINDOWS.toString(), "dump", "xmltree", apkFilePath, "--file", "AndroidManifest.xml"};
        LOG.info("Executing AAPT2 using command: {}", Arrays.toString(cmd));
        return exec(cmd).getInputStream();
    }

    private OSType getOSType()
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

    private Process exec(final String... command) throws IOException
    {
        return new ProcessBuilder().command(command)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .redirectInput(ProcessBuilder.Redirect.INHERIT)
                .redirectOutput(ProcessBuilder.Redirect.PIPE).start();
    }

    private void copyFile(final String src, final Path dst, final OSType type) throws IOException
    {
        try (final InputStream stream = ClassLoader.getSystemClassLoader().getResourceAsStream(src))
        {
            if (stream == null)
                throw new IllegalStateException("Cannot copy missing resource: " + src);
            Files.copy(stream, dst, StandardCopyOption.REPLACE_EXISTING);
            if (type == OSType.LINUX)
            {
                final Set<PosixFilePermission> permissions = Sets.newHashSet();
                permissions.add(PosixFilePermission.OWNER_EXECUTE);
                Files.setPosixFilePermissions(AAPT2_LOCAL_PATH_LINUX, permissions);
            }
        }
    }
}
