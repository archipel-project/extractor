package org.archipel.extractors;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.minecraft.network.NetworkSide;
import net.minecraft.network.NetworkState;

public class TypesExtractor implements Extractor
{
    @Override
    public JsonElement extract()
    {
        final JsonObject types = new JsonObject();
        final JsonObject networkState = new JsonObject();
        final JsonObject enumNetworkState = new JsonObject();

        for (final NetworkState value : NetworkState.values())
            enumNetworkState.addProperty(value.name(), value.getId());

        networkState.add("enum", enumNetworkState);
        networkState.addProperty("repr", "varint");

        types.add("NetworkState", networkState);

        final JsonObject networkSide = new JsonObject();
        final JsonObject enumNetworkSide = new JsonObject();
        for (final NetworkSide value : NetworkSide.values())
            enumNetworkSide.addProperty(value.name(), value.ordinal());
        networkSide.add("enum", enumNetworkSide);
        networkSide.addProperty("repr", "varint");
        types.add("NetworkSide", networkSide);

        return types;
    }

    @Override
    public String getName()
    {
        return "types";
    }
}
