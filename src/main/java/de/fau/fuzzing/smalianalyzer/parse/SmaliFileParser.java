package de.fau.fuzzing.smalianalyzer.parse;

import com.google.common.collect.SetMultimap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
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
                if (line.startsWith(".class"))
                    header.setClassName(line.substring(line.lastIndexOf(' ')).trim());
                else if (line.startsWith(".super"))
                    header.setSuperName(line.substring(line.lastIndexOf(' ')).trim());

                if (header.getClassName() != null && header.getSuperName() != null)
                    break;
            }

            if (header.getClassName() == null || header.getSuperName() == null)
                throw new IllegalStateException(String.format("Invalid smali file: %s", filePath.toString()));
            return header;
        }
    }

    public static void parseMethod(final Path filePath, final String methodName, final Map<String, Index> indexMap,
                                   final SetMultimap<String, String> intentResultMap, final SetMultimap<String, String> bundleResultMap, int depth) throws IOException
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
                    final Map<String, String> registerMap = new HashMap<>();
                    while ((line = reader.readLine()) != null)
                    {
                        line = line.trim();
                        if (line.matches(INVOKE_METHOD))
                        {
                            final String caller = line.substring(line.lastIndexOf(", ") + 2, line.indexOf("->"));
                            final String name = line.substring(line.indexOf("->") + 2, line.lastIndexOf('('));
                            final String[] registers = Pattern.compile(", ").split(line.substring(line.indexOf('{') + 1, line.indexOf('}')));

                            if (Constants.INTENT_CLASS.equals(caller) && name.toLowerCase().contains("get"))
                            {
                                if (registers.length > 1)
                                {
                                    final String value = registerMap.getOrDefault(registers[1], null);
                                    if (value != null)
                                        intentResultMap.put(name, value);
                                }
                            }
                            else if (Constants.BUNDLE_CLASS.equals(caller) && name.toLowerCase().contains("get"))
                            {
                                if (registers.length > 1)
                                {
                                    final String value = registerMap.getOrDefault(registers[1], null);
                                    if (value != null)
                                        bundleResultMap.put(name, value);
                                }
                            }
                            else if (indexMap.get(caller) != null && depth < Constants.MAX_DEPTH)
                            {
                                final Index index = indexMap.get(caller);
                                final String fullName = line.substring(line.indexOf("->") + 2);
                                parseMethod(index.getFilePath(), fullName, indexMap, intentResultMap, bundleResultMap, depth + 1);

                            }
                        }
                        else if (line.matches(SET_CONST_STRING))
                        {
                            final String register = line.substring(line.indexOf(' ') + 1, line.indexOf(','));
                            final String value = line.substring(line.indexOf('\"') + 1, line.lastIndexOf('\"'));
                            registerMap.put(register, value);
                        }
                    }
                }
            }
        }
    }
}
