package org.archipel;

import com.google.gson.GsonBuilder;
import net.fabricmc.api.ModInitializer;
import org.archipel.extractors.Extractor;
import org.archipel.extractors.TypesExtractor;
import org.archipel.extractors.protocol.ProtocolExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class Main implements ModInitializer {
    public static final Logger LOGGER = LoggerFactory.getLogger("extractor");

    private static final Extractor[] EXTRACTORS = {
            new TypesExtractor(),
            new ProtocolExtractor()
    };

    @Override
    public void onInitialize() {
        LOGGER.info("Starting extraction...");

        Path outputDir;

        try {
            outputDir = Files.createDirectories(Paths.get("extracted"));
        } catch (IOException e) {
            LOGGER.error("Failed to create output directory", e);
            return;
        }

        var gson = new GsonBuilder().setPrettyPrinting().create();

        for (var ext : EXTRACTORS) {
            try (var writer = Files.newBufferedWriter(outputDir.resolve(ext.getName() + ".json"))) {
                gson.toJson(ext.extract(), writer);
                LOGGER.info("... extracted " + ext.getName());
            } catch (IOException e) {
                LOGGER.error("Failed to extract " + ext.getName(), e);
            }
        }

        System.exit(0);
    }
}
