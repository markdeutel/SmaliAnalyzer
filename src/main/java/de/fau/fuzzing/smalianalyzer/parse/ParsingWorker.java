package de.fau.fuzzing.smalianalyzer.parse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ParsingWorker extends Thread
{
    private static final Logger LOG = LogManager.getLogger(SmaliParser.class.getName());

    private final List<Path> componentPaths;
    private final SmaliFileVisitor.InvocationCallers invocationCallers;
    final Map<String, SmaliParser.Component> result = new HashMap<>();
    private int start, end;

    public ParsingWorker(int start, int end, final List<Path> componentPaths,
                         final SmaliFileVisitor.InvocationCallers invocationCallers)
    {
        this.start = start;
        this.end = end;
        this.componentPaths = componentPaths;
        this.invocationCallers = invocationCallers;
    }

    public Map<String, SmaliParser.Component> getResult()
    {
        return result;
    }

    @Override
    public void run()
    {
        for (int i = start; i < end; ++i)
        {
            try
            {
                final SmaliParser.Component component = SmaliParser.parseComponent(componentPaths.get(i), invocationCallers);
                if (!component.getIntentInvocations().isEmpty() || !component.getBundleInvocations().isEmpty())
                    result.put(component.getClassName(), component);
            }
            catch (Exception e)
            {
                LOG.error("Error while parsing components:", e);
            }
        }
    }
}
