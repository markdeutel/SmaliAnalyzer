package de.fau.fuzzing.smalianalyzer.parser;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * @author Mark Deutel
 */
public class SmaliFileVisitor extends SimpleFileVisitor<Path>
{
    private static final Logger LOG = LogManager.getLogger(SmaliFileVisitor.class.getName());
    private static final Path POISON_PILL = Paths.get("kill/yourself");

    public static class InvocationCallers
    {
        private SetMultimap<String, String> intentInvocationCallers = HashMultimap.create();
        private SetMultimap<String, String> bundleInvocationCallers = HashMultimap.create();

        private int size()
        {
            return intentInvocationCallers.size() + bundleInvocationCallers.size();
        }

        private void append(final InvocationCallers other)
        {
            this.intentInvocationCallers.putAll(other.intentInvocationCallers);
            this.bundleInvocationCallers.putAll(other.bundleInvocationCallers);
        }

        public SetMultimap<String, String> getIntentInvocationCallers()
        {
            return intentInvocationCallers;
        }

        public SetMultimap<String, String> getBundleInvocationCallers()
        {
            return bundleInvocationCallers;
        }
    }

    private static class InvocationCallerWorker extends Thread
    {
        private final InvocationCallers invocationCallers = new InvocationCallers();
        private final BlockingDeque<Path> taskQueue;
        private final Set<String> components;

        private InvocationCallerWorker(final Set<String> components, final BlockingDeque<Path> taskQueue)
        {
            this.components = components;
            this.taskQueue = taskQueue;
        }

        private InvocationCallers getInvocationCallers()
        {
            return invocationCallers;
        }

        @Override
        public void run()
        {
            while (true)
            {
                try
                {
                    final Path path = taskQueue.take();
                    if (path == POISON_PILL)
                        break;

                    final SmaliParser.ClassHeader header = SmaliParser.peekHeader(path);
                    if (!components.contains(header.getName()))
                    {
                        final SmaliParser.Class klass = SmaliParser.parse(path);
                        for (final String methodName : klass.getMethods().keySet())
                        {
                            final SmaliParser.Method method = klass.getMethods().get(methodName);
                            if (!method.getIntentMethods().isEmpty())
                                invocationCallers.intentInvocationCallers.put(header.getName(), methodName);
                            if (!method.getBundleMethods().isEmpty())
                                invocationCallers.bundleInvocationCallers.put(header.getName(), methodName);
                        }
                    }
                }
                catch (Exception e)
                {
                    LOG.error("Error while searching for invocation callers:", e);
                }
            }
        }
    }

    private static class ComponentWorker extends Thread
    {
        private final BlockingDeque<Path> taskQueue;
        private Set<String> searchComponents;
        private Set<String> components = new HashSet<>();

        private ComponentWorker(final Set<String> searchComponents, final BlockingDeque<Path> taskQueue)
        {
            this.searchComponents = searchComponents;
            this.taskQueue = taskQueue;
        }


        private Set<String> getComponents()
        {
            return components;
        }

        @Override
        public void run()
        {
            while (true)
            {
                try
                {
                    final Path path = taskQueue.take();
                    if (path == POISON_PILL)
                        break;

                    final SmaliParser.ClassHeader header = SmaliParser.peekHeader(path);
                    if (searchComponents.contains(header.getSuperClass()))
                    {
                        searchComponents.add(header.getName());
                        components.add(header.getName());
                    }
                }
                catch (Exception e)
                {
                    LOG.error("Error while searching for component:", e);
                }
            }
        }
    }

    private final BlockingDeque<Path> taskQueue;

    private SmaliFileVisitor(final BlockingDeque<Path> taskQueue)
    {
        this.taskQueue = taskQueue;
    }

    public static InvocationCallers searchFileTreeForInvocationCallers(final Path rootPath, final Set<String> components)
    {
        try
        {
            LOG.info("Searching invocation caller");
            int numThreads = Runtime.getRuntime().availableProcessors();
            final InvocationCallers invocationCallers = new InvocationCallers();
            final BlockingDeque<Path> taskQueue = new LinkedBlockingDeque<>();
            Thread[] workers = new Thread[numThreads];
            for (int i = 0; i < numThreads; ++i)
            {
                workers[i] = new InvocationCallerWorker(components, taskQueue);
                workers[i].start();
            }

            final SmaliFileVisitor fileVisitor = new SmaliFileVisitor(taskQueue);
            Files.walkFileTree(rootPath, fileVisitor);

            for (int i = 0; i < numThreads; ++i)
            {
                taskQueue.put(POISON_PILL);
            }

            for (int i = 0; i < numThreads; ++i)
            {
                workers[i].join();
                invocationCallers.append(((InvocationCallerWorker) workers[i]).getInvocationCallers());
            }

            LOG.info("Found {}", invocationCallers.size());
            return invocationCallers;
        }
        catch (Exception e)
        {
            LOG.error("Failed searching for invocation callers:", e);
            return null;
        }
    }

    public static Set<String> searchFileTreeForComponents(final Path rootPath)
    {
        try
        {
            LOG.info("Searching components");
            Set<String> components = Sets.newHashSet();
            Set<String> searchComponents = Sets.newHashSet(
                    "Landroid/app/Activity;", "Landroid/accounts/AccountAuthenticatorActivity;",
                    "android/app/ActivityGroup;", "Landroid/app/AliasActivity;", "Landroid/app/AliasActivity;",
                    "Landroid/app/ListActivity;", "Landroid/app/NativeActivity;", "Landroid/app/Service;",
                    "Landroid/content/BroadcastReceiver;", "Landroid/appwidget/AppWidgetProvider;",
                    "Landroid/app/admin/DeviceAdminReceiver;", "Landroid/telephony/mbms/MbmsDownloadReceiver;",
                    "Landroid/service/restrictions/RestrictionsReceiver;");

            int count;
            final BlockingDeque<Path> taskQueue = new LinkedBlockingDeque<>();
            final SmaliFileVisitor fileVisitor = new SmaliFileVisitor(taskQueue);

            int numThreads = Runtime.getRuntime().availableProcessors();
            Thread[] workers = new Thread[numThreads];

            do
            {
                count = searchComponents.size();
                for (int i = 0; i < numThreads; ++i)
                {
                    workers[i] = new ComponentWorker(searchComponents, taskQueue);
                    workers[i].start();
                }

                Files.walkFileTree(rootPath, fileVisitor);

                for (int i = 0; i < numThreads; ++i)
                    taskQueue.put(POISON_PILL);

                for (int i = 0; i < numThreads; ++i)
                {
                    workers[i].join();
                    searchComponents.addAll(((ComponentWorker) workers[i]).getComponents());
                    components.addAll(((ComponentWorker) workers[i]).getComponents());
                }
            }
            while (searchComponents.size() != count);

            LOG.info("Found {}", components.size());
            return components;
        }
        catch (Exception e)
        {
            LOG.error("Failed searching for components:", e);
            return null;
        }
    }

    @Override
    public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes)
    {
        final PathMatcher fileMatcher = FileSystems.getDefault().getPathMatcher("glob:**.smali");
        if (fileMatcher.matches(path))
        {
            try
            {
                taskQueue.put(path);
            }
            catch (InterruptedException e)
            {
                LOG.error("Error while searching for invocation callers:", e);
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
