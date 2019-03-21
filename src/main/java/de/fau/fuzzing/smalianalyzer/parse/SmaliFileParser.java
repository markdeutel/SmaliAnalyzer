package de.fau.fuzzing.smalianalyzer.parse;

import com.google.common.collect.Maps;
import com.google.common.collect.SetMultimap;
import de.fau.fuzzing.smalianalyzer.ApplicationProperties;
import de.fau.fuzzing.smalianalyzer.Constants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class SmaliFileParser
{
    private static final Logger LOG = LogManager.getLogger();

    private static final String INVOKE_METHOD = "invoke-.* .*";
    private static final String SET_CONST_STRING = "(const-string|const-string/jumbo) .., \".*\"";

    public static SmaliHeader parseSmaliHeader(final Path filePath) throws IOException
    {
        try (BufferedReader reader = Files.newBufferedReader(filePath))
        {
            String line;
            final SmaliHeader header = new SmaliHeader();
            while ((line = reader.readLine()) != null)
            {
                line = line.trim();
                if (line.isEmpty())
                    continue;
                if (line.equals("# direct methods") || line.equals("# static fields") || line.equals("# annotations"))
                    break;

                final String name = line.substring(line.lastIndexOf(' ')).trim();
                if (line.startsWith(".class"))
                    header.setClassName(name);
                else if (line.startsWith(".super"))
                    header.setSuperName(name);
                else if (line.startsWith(".implements"))
                    header.addImplementedClass(name);
            }

            if (header.getClassName() == null || header.getSuperName() == null)
                throw new IllegalStateException(String.format("Invalid smali file: %s", filePath.toString()));
            return header;
        }
    }

    public static void parseMethod(final Path filePath, final String methodName, final Map<String, IndexEntry> indexMap, final Map<String, String> registerMap,
                                   final SetMultimap<String, String> intentResultMap, final SetMultimap<String, String> bundleResultMap,
                                   final Set<String> stringSet, int depth) throws IOException
    {
        try (BufferedReader reader = Files.newBufferedReader(filePath))
        {
            String line;
            while ((line = reader.readLine()) != null)
            {
                line = line.trim();
                if (line.startsWith(".method") && line.endsWith(methodName))
                {
                    // found method
                    LOG.debug("Parsing method: {}", methodName);
                    while ((line = reader.readLine()) != null)
                    {
                        line = line.trim();
                        if (line.matches(INVOKE_METHOD)) // handles method invocation
                        {
                            final String caller = line.substring(line.lastIndexOf(", ") + 2, line.indexOf("->"));
                            final String name = line.substring(line.indexOf("->") + 2, line.lastIndexOf('('));
                            final String[] registers = Pattern.compile(", ").split(line.substring(line.indexOf('{') + 1, line.indexOf('}')));

                            if (Constants.INTENT_CLASS.equals(caller) && name.toLowerCase().contains("get"))
                            {
                                if (registers.length > 1)
                                {
                                    final String value = registerMap.get(registers[1]);
                                    if (value != null)
                                        intentResultMap.put(name, value);
                                }
                            }
                            else if (Constants.BUNDLE_CLASS.equals(caller) && name.toLowerCase().contains("get"))
                            {
                                if (registers.length > 1)
                                {
                                    final String value = registerMap.get(registers[1]);
                                    if (value != null)
                                        bundleResultMap.put(name, value);
                                }
                            }
                            else if (indexMap.get(caller) != null && depth < ApplicationProperties.getInstance().getMaxDepth())
                            {
                                final IndexEntry index = indexMap.get(caller);
                                final String fullName = line.substring(line.indexOf("->") + 2);

                                int paramCount = 0;
                                int startIndex = line.startsWith("invoke-static") ? 0 : 1;
                                final Map<String, String> subRegisterMap = Maps.newHashMap();
                                for (int i = startIndex; i < registers.length; ++i)
                                {
                                    final String value = registerMap.get(registers[i]);
                                    if (value != null)
                                        subRegisterMap.put("p" + paramCount, value);
                                    paramCount++;
                                }

                                parseMethod(index.getFilePath(), fullName, indexMap, subRegisterMap, intentResultMap, bundleResultMap, stringSet, depth + 1);
                            }
                        }
                        else if (line.matches(SET_CONST_STRING)) // handles constants strings
                        {
                            final String register = line.substring(line.indexOf(' ') + 1, line.indexOf(','));
                            final String value = line.substring(line.indexOf('\"') + 1, line.lastIndexOf('\"'));
                            registerMap.put(register, value);
                            if (value.trim().length() > 1)
                                stringSet.add(value.trim());
                        }
                    }
                }
            }
        }
    }

    public static void parseParcelableClass(final Path filePath, final Map<String, String> resultMap) throws IOException
    {
        try(final BufferedReader reader = Files.newBufferedReader(filePath))
        {
            String line;
            while ((line = reader.readLine()) != null)
            {
                line = line.trim();
                if (line.startsWith(".field") && !line.contains("static"))
                {
                    final String[] tokens = line.split(" ");
                    if (tokens.length >= 2)
                    {
                        final String[] var = tokens[tokens.length - 1].split(":");
                        if (var.length == 2)
                        {
                            resultMap.put(var[0], var[1]);
                        }
                    }
                }
                else if (line.startsWith(".method"))
                {
                    break;
                }
            }
        }
    }
}
