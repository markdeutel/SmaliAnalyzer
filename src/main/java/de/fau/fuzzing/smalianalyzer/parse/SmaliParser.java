package de.fau.fuzzing.smalianalyzer.parse;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

public class SmaliParser
{
    private static final Logger LOG = LogManager.getLogger(SmaliParser.class.getName());

    private static final String INTENT_CLASS = "Landroid/content/Intent;";
    private static final String BUNDLE_CLASS = "Landroid/os/Bundle;";

    private static final String CLASS_NAME = "\\.class .*;";
    private static final String SUPER_CLASS = "\\.super .*;";

    private static final String BEGIN_METHOD = "\\.method .* .*\\(.*\\).*";
    private static final String END_METHOD = "\\.end method";
    private static final String INVOKE_METHOD_TEMPLATE = "invoke-.* %s->.*";
    private static final String SET_CONST_STRING = "(const-string|const-string/jumbo) .., \".*\"";
    private static final int MAX_SEARCH_DEPTH = 10;

    private static final String ACTIVITY_START_COMMAND = "onCreate(Landroid/os/Bundle;)V";
    private static final String SERVICE_START_COMMAND = "onStartCommand(Landroid/content/Intent;II)I";
    private static final String BROADCAST_RECEIVER_START_COMMAND = "onReceive(Landroid/content/Context;Landroid/content/Intent;)V";

    public static class ClassHeader
    {
        private String name = "";
        private String superClass = "";

        public String getName()
        {
            return name;
        }

        public String getSuperClass()
        {
            return superClass;
        }
    }

    public static class Class
    {
        private String className = "";
        private Map<String, Method> methods = new HashMap<>();

        public String getClassName()
        {
            return className;
        }

        public Map<String, Method> getMethods()
        {
            return methods;
        }
    }

    public static class Component
    {
        private Component(final String className)
        {
            this.className = className.substring(1, className.length() - 1).replaceAll("/", "\\.");
        }

        private transient String className;
        private SetMultimap<String, String> intentInvocations = HashMultimap.create();
        private SetMultimap<String, String> bundleInvocations = HashMultimap.create();

        public String getClassName()
        {
            return className;
        }

        public SetMultimap<String, String> getIntentInvocations()
        {
            return intentInvocations;
        }

        public SetMultimap<String, String> getBundleInvocations()
        {
            return bundleInvocations;
        }
    }

    public static class Method
    {
        private List<String> selfMethods = new ArrayList<>();
        private List<Invocation> intentMethods = new ArrayList<>();
        private List<Invocation> bundleMethods = new ArrayList<>();

        public List<String> getSelfMethods()
        {
            return selfMethods;
        }

        public List<Invocation> getIntentMethods()
        {
            return intentMethods;
        }

        public List<Invocation> getBundleMethods()
        {
            return bundleMethods;
        }
    }

    public static class Invocation
    {
        private String name = "";
        private String value = "";

        public String getName()
        {
            return name;
        }

        public String getValue()
        {
            return value;
        }
    }

    public static ClassHeader peekHeader(final Path filePath) throws IOException
    {
        LOG.debug("---------------------------------------------------");
        LOG.debug("Peeking file header: {}", filePath.getFileName().toString());
        try (BufferedReader reader = Files.newBufferedReader(filePath))
        {
            final ClassHeader header = new ClassHeader();
            header.name = reader.readLine();
            if (header.name == null || !header.name.matches(CLASS_NAME))
                return null;
            header.name = header.name.substring(header.name.lastIndexOf(' ') + 1);
            header.superClass = reader.readLine();
            if (header.superClass == null || !header.superClass.matches(SUPER_CLASS))
                return null;
            header.superClass = header.superClass.substring(header.superClass.lastIndexOf(' ') + 1);
            return header;
        }
    }

    public static Class parse(final Path filePath, final SmaliFileVisitor.InvocationCallers invocationCallers) throws IOException
    {
        LOG.debug("---------------------------------------------------");
        LOG.debug("Parsing file: {}", filePath.getFileName().toString());
        try (BufferedReader reader = Files.newBufferedReader(filePath))
        {
            String line;
            final Class klass = new Class();
            while ((line = reader.readLine()) != null)
            {
                // loop until next method begins
                line = line.trim();
                if (line.matches(CLASS_NAME))
                    klass.className = line.substring(line.lastIndexOf(' ') + 1);

                if (!line.matches(BEGIN_METHOD) || klass.className == null)
                    continue;

                // parse method
                final String methodName = line.substring(line.lastIndexOf(' ') + 1);
                LOG.debug("Found method: {}", methodName);

                final Method method = new Method();
                final Map<String, String> registerMap = new HashMap<>();
                while ((line = reader.readLine()) != null)
                {
                    // if end of method is reached end inner loop
                    line = line.trim();
                    if (line.matches(END_METHOD))
                        break;

                    // check for intent caller calls
                    if (invocationCallers != null)
                    {
                        for (final String intentCaller : invocationCallers.getIntentInvocationCallers().keySet())
                        {
                            if (line.matches(String.format(INVOKE_METHOD_TEMPLATE, intentCaller)))
                            {
                                final Invocation invocation = parseIntentInvocationLine(line, registerMap);
                                if (invocationCallers.getIntentInvocationCallers().get(intentCaller).contains(invocation.getName()))
                                    method.intentMethods.add(invocation);
                            }
                        }

                        for (final String bundleCaller : invocationCallers.getBundleInvocationCallers().keySet())
                        {
                            if (line.matches(String.format(INVOKE_METHOD_TEMPLATE, bundleCaller)))
                            {
                                final Invocation invocation = parseIntentInvocationLine(line, registerMap);
                                if (invocationCallers.getBundleInvocationCallers().get(bundleCaller).contains(invocation.getName()))
                                    method.bundleMethods.add(invocation);
                            }
                        }
                    }

                    // check for intent calls
                    if (line.matches(String.format(INVOKE_METHOD_TEMPLATE, INTENT_CLASS)))
                    {
                        final Invocation invocation = parseIntentInvocationLine(line, registerMap);
                        if (invocation.name.toLowerCase().contains("get"))
                            method.intentMethods.add(invocation);
                    }
                    // check for bundles
                    else if (line.matches(String.format(INVOKE_METHOD_TEMPLATE, BUNDLE_CLASS)))
                    {
                        final Invocation invocation = parseIntentInvocationLine(line, registerMap);
                        if (invocation.name.toLowerCase().contains("get"))
                            method.bundleMethods.add(invocation);
                    }
                    // check for invocations of own classes
                    else if (line.matches(String.format(INVOKE_METHOD_TEMPLATE, klass.className)))
                    {
                        method.selfMethods.add(line.substring(line.indexOf("->") + 2));
                    }
                    // check for loading of registers
                    else if (line.matches(SET_CONST_STRING))
                    {
                        final String register = line.substring(line.indexOf(' ') + 1, line.indexOf(','));
                        final String value = line.substring(line.indexOf('\"') + 1, line.lastIndexOf('\"'));
                        registerMap.put(register, value);
                    }

                }
                klass.methods.put(methodName, method);
            }
            return klass;
        }
    }

    public static Class parse(final Path filePath) throws IOException
    {
        return parse(filePath, null);
    }

    public static Component parseComponent(final Path filePath,
                                           final SmaliFileVisitor.InvocationCallers invocationCallers) throws IOException
    {
        final Class klass = parse(filePath, invocationCallers);
        final Component component = new Component(klass.className);

        addToResult(klass.methods, component, ACTIVITY_START_COMMAND, 0);
        addToResult(klass.methods, component, SERVICE_START_COMMAND, 0);
        addToResult(klass.methods, component, BROADCAST_RECEIVER_START_COMMAND, 0);
        return component;
    }

    public static Map<String, Component> parseComponents(final Path rootPath, final Collection<String> components,
                                                         final SmaliFileVisitor.InvocationCallers invocationCallers)
    {
        LOG.info("Parsing component classes");
        final List<Path> componentPaths = new ArrayList<>(components.size());
        for (final String component : components)
            componentPaths.add(getComponentPath(rootPath, component));

        try
        {
            final Map<String, SmaliParser.Component> result = new HashMap<>();

            int numThreads = Runtime.getRuntime().availableProcessors();
            int stride = componentPaths.size() / numThreads;
            Thread workers[] = new Thread[numThreads];
            for (int i = 0; i < numThreads; ++i)
            {
                int start = i * stride;
                int end = start + stride;
                if (i == workers.length - 1)
                    end = componentPaths.size();

                workers[i] = new ParsingWorker(start, end, componentPaths, invocationCallers);
                workers[i].start();
            }

            for (int i = 0; i < numThreads; ++i)
            {
                workers[i].join();
                result.putAll(((ParsingWorker) workers[i]).getResult());
            }

            return result;
        }
        catch (Exception e)
        {
            LOG.error("Failed parsing components:", e);
            return null;
        }
    }

    private static void addToResult(final Map<String, Method> methods, final Component component, final String methodName, int depth)
    {
        final Method method = methods.get(methodName);
        if (method != null && depth <= MAX_SEARCH_DEPTH)
        {
            LOG.debug("Enter method: {}", methodName);
            LOG.debug("Found {} intent methods", method.intentMethods.size());
            for (final Invocation invocation : method.intentMethods)
                component.intentInvocations.put(invocation.name, invocation.value);
            for (final Invocation invocation : method.bundleMethods)
                component.bundleInvocations.put(invocation.name, invocation.value);
            for (final String subMethodName : method.selfMethods)
                addToResult(methods, component, subMethodName, depth + 1);
            LOG.debug("Leave method: {}", methodName);
        }
    }

    private static Invocation parseIntentInvocationLine(final String line, final Map<String, String> registerMap)
    {
        final Invocation invocation = new Invocation();
        invocation.name = line.substring(line.indexOf("->") + 2, line.indexOf('('));
        final String[] registers = Pattern.compile(", ").split(line.substring(line.indexOf('{') + 1, line.indexOf('}')));
        if (registers.length >= 2)
            invocation.value = registerMap.getOrDefault(registers[1], "");
        return invocation;
    }

    private static Path getComponentPath(final Path rootPath, final String componentClass)
    {
        return rootPath.resolve(componentClass.substring(1, componentClass.length() - 1).concat(".smali"));
    }
}
