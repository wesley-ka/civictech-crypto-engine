package com.civictech.crypto.engine.cleanup;

import com.civictech.crypto.engine.error.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class StorageCleanupService {

    private static final Logger log = LoggerFactory.getLogger(StorageCleanupService.class);

    private final S3Client s3Client;
    private final String storageType;
    private final String bucketName;
    private final Path storageRoot;

    public StorageCleanupService(@Autowired(required = false) S3Client s3Client,
                                 @Value("${voting.storage.type:local}") String storageType,
                                 @Value("${voting.storage.b2.bucket-name:}") String bucketName) {
        this.s3Client = s3Client;
        this.storageType = storageType;
        this.bucketName = bucketName;
        this.storageRoot = Paths.get("./local-storage");
    }

    private boolean isB2() {
        return "b2".equalsIgnoreCase(storageType) && s3Client != null;
    }

    @Scheduled(cron = "0 0 3 * * *") // Run daily at 3:00 AM
    public void cleanupOldData() {
        log.info("Starting scheduled cleanup of data older than 7 days...");
        Instant cutOffTime = Instant.now().minus(7, ChronoUnit.DAYS);

        if (isB2()) {
            cleanupB2(cutOffTime);
        } else {
            cleanupLocal(cutOffTime);
        }
    }

    private void cleanupB2(Instant cutOffTime) {
        try {
            // List all objects in the B2 bucket (single API call)
            ListObjectsV2Response response = s3Client.listObjectsV2(
                    ListObjectsV2Request.builder().bucket(bucketName).build());

            // Group B2 objects by their session/asset/vc prefixes
            Map<String, List<S3Object>> groups = new HashMap<>();

            for (S3Object obj : response.contents()) {
                String key = obj.key();
                String groupKey = getGroupKey(key);
                if (groupKey != null) {
                    groups.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(obj);
                }
            }

            // Delete groups where the latest file is older than 7 days
            for (Map.Entry<String, List<S3Object>> entry : groups.entrySet()) {
                String groupPrefix = entry.getKey();
                List<S3Object> objects = entry.getValue();

                Instant latestModified = objects.stream()
                        .map(S3Object::lastModified)
                        .max(Instant::compareTo)
                        .orElse(Instant.MIN);

                if (latestModified.isBefore(cutOffTime)) {
                    log.info("B2 group '{}' is expired (last modified: {}). Purging objects...", 
                            groupPrefix, latestModified);
                    for (S3Object obj : objects) {
                        try {
                            s3Client.deleteObject(DeleteObjectRequest.builder()
                                    .bucket(bucketName)
                                    .key(obj.key())
                                    .build());
                            log.debug("Deleted B2 object: {}", obj.key());
                        } catch (Exception e) {
                            log.warn("Failed to delete B2 key: {}", obj.key(), e);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to perform B2 storage cleanup", e);
        }
    }

    private String getGroupKey(String key) {
        if (key.startsWith("voting/") || key.startsWith("ledger/")) {
            int firstSlash = key.indexOf('/');
            int secondSlash = key.indexOf('/', firstSlash + 1);
            if (secondSlash > 0) {
                return key.substring(0, secondSlash + 1);
            }
            return key;
        } else if (key.startsWith("vc/")) {
            return key; // Individual files under vc/ are treated as unique groups
        }
        return null;
    }

    private void cleanupLocal(Instant cutOffTime) {
        String[] subFolders = {"voting", "ledger", "vc"};
        for (String sub : subFolders) {
            Path subPath = storageRoot.resolve(sub);
            if (!Files.exists(subPath) || !Files.isDirectory(subPath)) {
                continue;
            }

            File[] children = subPath.toFile().listFiles();
            if (children == null) continue;

            for (File child : children) {
                if (child.isDirectory()) {
                    long maxLastModified = getMaxLastModifiedRecursive(child);
                    Instant lastModInstant = Instant.ofEpochMilli(maxLastModified);
                    if (lastModInstant.isBefore(cutOffTime)) {
                        log.info("Local directory '{}' is expired (last modified: {}). Deleting...", 
                                child.getAbsolutePath(), lastModInstant);
                        deleteDirectory(child);
                    }
                } else if (child.isFile()) {
                    Instant lastModInstant = Instant.ofEpochMilli(child.lastModified());
                    if (lastModInstant.isBefore(cutOffTime)) {
                        log.info("Local file '{}' is expired (last modified: {}). Deleting...", 
                                child.getAbsolutePath(), lastModInstant);
                        child.delete();
                    }
                }
            }
        }
    }

    private long getMaxLastModifiedRecursive(File file) {
        if (file.isFile()) {
            return file.lastModified();
        }
        long max = file.lastModified();
        File[] children = file.listFiles();
        if (children != null) {
            for (File c : children) {
                max = Math.max(max, getMaxLastModifiedRecursive(c));
            }
        }
        return max;
    }

    private void deleteDirectory(File dir) {
        File[] allContents = dir.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        dir.delete();
    }
}
