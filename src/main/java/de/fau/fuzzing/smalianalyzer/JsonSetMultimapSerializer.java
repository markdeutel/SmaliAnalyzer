package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.SetMultimap;
import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.lang.reflect.Type;

public class JsonSetMultimapSerializer implements JsonSerializer<SetMultimap>
{
    @Override
    public JsonElement serialize(SetMultimap setMultimap, Type type, JsonSerializationContext context)
    {
        return context.serialize(setMultimap.asMap());
    }
}
