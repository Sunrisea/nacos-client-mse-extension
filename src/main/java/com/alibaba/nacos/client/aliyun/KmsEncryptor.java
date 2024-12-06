package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.config.filter.IConfigRequest;
import com.alibaba.nacos.api.config.filter.IConfigResponse;
import com.alibaba.nacos.api.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.function.Supplier;

import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_128_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_256_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CONTENT;
import static com.alibaba.nacos.client.aliyun.AliyunConst.DATA_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.ENCODE_UTF8;
import static com.alibaba.nacos.client.aliyun.AliyunConst.ENCRYPTED_DATA_KEY;
import static com.alibaba.nacos.client.aliyun.AliyunConst.GROUP;
import static com.alibaba.nacos.client.aliyun.AliyunConst.STRING_VALUE_BLANK_ERROR_MSG_FORMAT;

public abstract class KmsEncryptor {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(AliyunConfigFilter.class);
    
    private KmsLocalCache kmsLocalCache;
    
    public static final int defaultRetryTimes = 3;
    
    public static final int defaultRetryIntervalMilliseconds = 2 * 100;
    
    public static final int defaultTimeoutMilliseconds = 3 * 1000;
    
    public boolean isUseLocalCache;
    
    public KmsEncryptor(Properties properties){
        this.isUseLocalCache = KmsUtils.parsePropertyValue(properties, AliyunConst.NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_SWITCH,
                AliyunConst.DEFAULT_KMS_LOCAL_CACHE_SWITCH);
        if (this.isUseLocalCache()) {
            LOGGER.info("using kms encryption local cache.");
            this.kmsLocalCache = new KmsLocalCache(properties);
        }
    }
    
    public String encrypt(IConfigRequest configRequest) throws Exception {
        checkIfKmsClientIsReady();
        checkKeyId();
        protectKeyId();
        
        String dataId = (String) configRequest.getParameter(DATA_ID);
        String group = (String) configRequest.getParameter(GROUP);
        String plainContent = (String) configRequest.getParameter(CONTENT);
        String plainDataKey = null;
        String encryptedDataKey = null;
        String result = null; //encryptedContent
        String blankResultErrorMsg = "encrypt from kms failed.";
        //        Exception requestKmsException = null;
        
        //prefer to use kms service
        try {
            if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
                String keySpec = KmsUtils.getKeySpecByDataIdPrefix(dataId);
                DataKey dataKey = generateDataKey(keySpec);
                plainDataKey = dataKey.getPlainDataKey();
                throwExceptionIfStringBlankWithErrorKey(plainDataKey, GroupKeyUtils.getGroupKey2(dataId, group),
                        "generateDataKeyResponse.getPlaintext()", "plainDataKey");
                encryptedDataKey = dataKey.getEncryptedDataKey();
                throwExceptionIfStringBlankWithErrorKey(encryptedDataKey, GroupKeyUtils.getGroupKey2(dataId, group),
                        "generateDataKeyResponse.getCiphertextBlob()", "encryptedDataKey");
                configRequest.putParameter(ENCRYPTED_DATA_KEY, encryptedDataKey);
                result = AesUtils.encrypt(plainContent, plainDataKey, ENCODE_UTF8);
            } else if (dataId.startsWith(CIPHER_PREFIX)) {
                result = encrypt(plainContent);
            }
        } catch (Exception e) {
            LOGGER.error("encrypt config:[{}] failed by using kms service: {}.",
                    GroupKeyUtils.getGroupKey2(dataId, group), e.getMessage(), e);
            throw e;
        }
        
        throwExceptionIfStringBlankWithErrorKey(result, GroupKeyUtils.getGroupKey2(dataId, group), "encrypt failed", blankResultErrorMsg);
        
        //update local cache
        this.updateLocalCacheItem(group, dataId, encryptedDataKey, result, plainDataKey, plainContent);
        return result;
        
    }
    
    public abstract String encrypt(String plainText) throws Exception;
    
    public String decrypt(IConfigResponse configResponse) throws Exception {
        checkIfKmsClientIsReady();
        
        String dataId = (String) configResponse.getParameter(DATA_ID);
        String group = (String) configResponse.getParameter(GROUP);
        String encryptedContent = (String) configResponse.getParameter(CONTENT);
        String encryptedDataKey = (String) configResponse.getParameter(ENCRYPTED_DATA_KEY);
        String plainDataKey = null;
        String result = null;
        Exception requestKmsException = null;
        String blankResultErrorMsg = "decrypt from kms failed.";
        boolean isUsedCache = true;
        
        try {
            if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
                throwExceptionIfStringBlankWithErrorKey(encryptedDataKey, GroupKeyUtils.getGroupKey2(dataId, group),
                        "decrypt failed", "response.getParameter(ENCRYPTED_DATA_KEY)");
                plainDataKey = decrypt(encryptedDataKey);
                result = AesUtils.decrypt(encryptedContent, plainDataKey, ENCODE_UTF8);
            } else if (dataId.startsWith(CIPHER_PREFIX)) {
                result = decrypt(encryptedContent);
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            //use local cache protection
            LOGGER.error("decrypt config:[{}] failed by using kms service: {}.",
                    GroupKeyUtils.getGroupKey2(dataId, group), e.getMessage(), e);
            requestKmsException = e;
        }
        
        if (requestKmsException != null || StringUtils.isBlank(result)) {
            LOGGER.warn("decrypt config [{}] failed with exception or empty result by using kms service. try to use local cache.", GroupKeyUtils.getGroupKey2(dataId, group));
            result = getDecryptedContentByUsingLocalCache(group, dataId, encryptedDataKey, encryptedContent);
            if (requestKmsException != null && StringUtils.isBlank(result)) {
                throw requestKmsException;
            } else if (StringUtils.isBlank(result)) {
                blankResultErrorMsg += "and no kms decryption local cache.";
            }
        } else {
            isUsedCache = false;
        }
        throwExceptionIfStringBlankWithErrorKey(result, GroupKeyUtils.getGroupKey2(dataId, group), "decrypt failed", blankResultErrorMsg);
        if (!isUsedCache) {
            this.updateLocalCacheItem(group, dataId, encryptedDataKey, encryptedContent, plainDataKey, result);
        }
        return result;
    }
    
    public abstract String decrypt(String encryptedContent) throws Exception;
    
    public abstract void protectKeyId();
    
    public abstract DataKey generateDataKey(String keySpec) throws Exception;
    
    public abstract void checkIfKmsClientIsReady() throws Exception;
    
    public abstract void checkKeyId() throws Exception;
    
    public void updateLocalCacheItem(String group, String dataId, String encryptedDataKey, String encryptedContent, String plainDataKey, String plainContent) {
        if (!this.isLocalCacheAvailable()) {
            return;
        }
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            getKmsLocalCache().put(GroupKeyUtils.getGroupKey2(dataId, group), new KmsLocalCache.LocalCacheItem(encryptedDataKey, encryptedContent, plainDataKey));
        } else if(dataId.startsWith(CIPHER_PREFIX)) {
            getKmsLocalCache().put(GroupKeyUtils.getGroupKey2(dataId, group), new KmsLocalCache.LocalCacheItem(encryptedContent, plainContent));
        }
    }
    
    public boolean isUseLocalCache() {
        return this.isUseLocalCache;
    }
    
    public KmsLocalCache getKmsLocalCache() {
        return this.kmsLocalCache;
    }
    
    public boolean isLocalCacheAvailable() {
        return this.isUseLocalCache() && this.getKmsLocalCache()!= null;
    }
    
    
    public String getDecryptedContentByUsingLocalCache(String group, String dataId, String encryptedDataKey, String encryptedContent)
            throws Exception {
        KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId, encryptedDataKey, encryptedContent);
        if (localCacheItem != null) {
            if (!StringUtils.isBlank(localCacheItem.getPlainDataKey())) {
                return AesUtils.decrypt(encryptedContent, localCacheItem.getPlainDataKey(), ENCODE_UTF8);
            } else if (!StringUtils.isBlank(localCacheItem.getPlainContent())) {
                return localCacheItem.getPlainContent();
            }
        }
        return null;
    }
    
    public KmsLocalCache.LocalCacheItem getLocalCacheItem(String group, String dataId, String encryptDataKey, String encryptedContent) {
        //check if open local cache
        if (!this.isLocalCacheAvailable()) {
            return null;
        }
        
        //check if cache is ready
        KmsLocalCache.LocalCacheItem localCacheItem = this.getKmsLocalCache().get(GroupKeyUtils.getGroupKey2(dataId, group));
        if (localCacheItem == null) {
            return null;
        }
        
        //check if cache is valid
        if (!checkIfKmsCacheItemValidByDecrypt(localCacheItem, dataId, encryptDataKey, encryptedContent)) {
            return null;
        }
        return localCacheItem;
    }
    
    public KmsLocalCache.LocalCacheItem getLocalCacheItem(String group, String dataId, String plainText) {
        //check if open local cache
        if (!this.isLocalCacheAvailable()) {
            return null;
        }
        
        //check if cache is ready
        KmsLocalCache.LocalCacheItem localCacheItem = this.getKmsLocalCache().get(GroupKeyUtils.getGroupKey2(dataId, group));
        if (localCacheItem == null) {
            return null;
        }
        
        //check if cache is valid
        if (checkIfKmsCacheItemValidByEncrypt(localCacheItem, dataId, plainText)) {
            return null;
        }
        
        return localCacheItem;
    }
    
    public void locallyRunWithRetryTimesAndTimeout(Supplier<Boolean> runnable, int retryTimes, long timeout)
            throws Exception {
        int locallyRetryTimes = 0;
        Exception localException = null;
        long beginTime = System.currentTimeMillis();
        while (locallyRetryTimes++ < retryTimes && System.currentTimeMillis() < beginTime + timeout) {
            try {
                if (runnable.get()) {
                    break;
                }
            } catch (Exception e) {
                localException = e;
            }
            Thread.sleep(defaultRetryIntervalMilliseconds);
        }
        if (localException != null) {
            throw localException;
        }
    }
    
    private boolean checkIfKmsCacheItemValidByEncrypt(KmsLocalCache.LocalCacheItem localCacheItem, String dataId, String plainContent) {
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedDataKey())
                    && !StringUtils.isBlank(localCacheItem.getPlainDataKey());
        } else if (dataId.startsWith(CIPHER_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedContent())
                    && !StringUtils.isBlank(localCacheItem.getPlainContent())
                    && localCacheItem.getPlainContent().equals(plainContent);
        }
        return false;
    }
    
    private boolean checkIfKmsCacheItemValidByDecrypt(KmsLocalCache.LocalCacheItem localCacheItem, String dataId, String encryptedDataKey, String encryptedContent) {
        String encryptedContentMd5 = MD5Utils.md5Hex(encryptedContent, ENCODE_UTF8);
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedDataKey())
                    && !StringUtils.isBlank(localCacheItem.getEncryptedContentMD5())
                    && !StringUtils.isBlank(localCacheItem.getPlainDataKey())
                    && StringUtils.equals(localCacheItem.getEncryptedDataKey(), encryptedDataKey)
                    && StringUtils.equals(localCacheItem.getEncryptedContentMD5(), encryptedContentMd5);
        } else if (dataId.startsWith(CIPHER_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedContentMD5())
                    && !StringUtils.isBlank(localCacheItem.getPlainContent())
                    && StringUtils.equals(localCacheItem.getEncryptedContentMD5(), encryptedContentMd5);
        }
        return false;
    }
    
    public String readFileToString(String filePath) {
        File file = getFileByPath(filePath);
        if (file == null || !file.exists()) {
            return null;
        }
        try {
            Path path = Paths.get(file.getAbsolutePath());
            byte[] fileContent = Files.readAllBytes(path);
            return new String(fileContent, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    private File getFileByPath(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            String path = AliyunConfigFilter.class.getClassLoader().getResource("").getPath();
            if (!(file = new File(path + filePath)).exists()) {
                path = Paths.get(filePath).toAbsolutePath().toString();
                if (!(file = new File(path)).exists()) {
                    return null;
                }
            }
        }
        return file;
    }
    
    public void throwExceptionIfStringBlankWithErrorKey(String s, String groupKey,  String errorMsg, String errorKey) throws Exception {
        if (StringUtils.isBlank(s)) {
            throw new RuntimeException(String.format(STRING_VALUE_BLANK_ERROR_MSG_FORMAT, groupKey, errorMsg, errorKey)
                    + "For more information, please check: " + AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
        }
    }
    
    public static class DataKey {
        
        private String plainDataKey;
        
        private String encryptedDataKey;
        
        public String getPlainDataKey() {
            return plainDataKey;
        }
        
        public void setPlainDataKey(String plainDataKey) {
            this.plainDataKey = plainDataKey;
        }
        
        public String getEncryptedDataKey() {
            return encryptedDataKey;
        }
        
        public void setEncryptedDataKey(String encryptedDataKey) {
            this.encryptedDataKey = encryptedDataKey;
        }
    }
}
