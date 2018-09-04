package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashSet;
import java.util.Set;

class ComponentVisitor extends SimpleFileVisitor<Path>
{
    private static final Logger LOG = LogManager.getLogger(ComponentVisitor.class.getName());

    private Set<String> searchComponents = Sets.newHashSet(
            "Landroid/app/Activity;", "Landroid/accounts/AccountAuthenticatorActivity;",
            "android/app/ActivityGroup;", "Landroid/app/AliasActivity;", "Landroid/app/AliasActivity;",
            "Landroid/app/ListActivity;", "Landroid/app/NativeActivity;", "Landroid/app/Service;",
            "Landroid/content/BroadcastReceiver;", "Landroid/appwidget/AppWidgetProvider;",
            "Landroid/app/admin/DeviceAdminReceiver;", "Landroid/telephony/mbms/MbmsDownloadReceiver;",
            "Landroid/service/restrictions/RestrictionsReceiver;");

    private Set<String> components = new HashSet<>();

    static Set<String> searchFileTree(final Path rootPath) throws IOException
    {
        int count;
        final ComponentVisitor fileVisitor = new ComponentVisitor();
        do
        {
            count = fileVisitor.searchComponents.size();
            Files.walkFileTree(rootPath, fileVisitor);
        } while (fileVisitor.searchComponents.size() != count);
        return fileVisitor.components;
    }

    @Override
    public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException
    {
        final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.smali");
        if (fileMatcher.matches(path))
        {
            final SmaliParser.ClassHeader header = SmaliParser.peekHeader(path);
            if (searchComponents.contains(header.superClass))
            {
                searchComponents.add(header.name);
                components.add(header.name);
            }
        }

        return FileVisitResult.CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path path, IOException e)
    {
        LOG.error("Failed visiting file: {}", e);
        return FileVisitResult.CONTINUE;
    }
}
