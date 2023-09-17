package org.archipel.extractors.protocol;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.minecraft.network.NetworkSide;
import net.minecraft.network.NetworkState;
import org.archipel.Main;
import org.archipel.extractors.Extractor;

import java.util.TreeSet;

public final class ProtocolExtractor implements Extractor {
    @Override
    public JsonElement extract() {
        var protocol = new JsonObject();

        for (var side : NetworkSide.values()) {
            var states = new JsonObject();

            for (var state : NetworkState.values()) {
                Main.LOGGER.debug(state + " " + side + ":");

                var map = state.getPacketIdToPacketMap(side);
                var packets = new JsonArray();

                for (var id : new TreeSet<>(map.keySet())) {
                    var packet = map.get(id.intValue());
                    packets.add(PacketAnalyzer.analyze(packet));
                    //break; // TODO: debug only
                }

                states.add(state.name().toLowerCase(), packets);
                //break; // TODO: debug only
            }

            protocol.add(side == NetworkSide.CLIENTBOUND ? "s2c" : "c2s", states);
            //break; // TODO: debug only
        }

        return protocol;
    }

    @Override
    public String getName() {
        return "protocol";
    }
}
