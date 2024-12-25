package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyun.dkms.gcs.openapi.models.Config;
import com.aliyun.kms.KmsTransferAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.DecryptRequest;
import com.aliyuncs.kms.model.v20160120.DescribeKeyRequest;
import com.aliyuncs.kms.model.v20160120.DescribeKeyResponse;
import com.aliyuncs.kms.model.v20160120.EncryptRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import com.aliyuncs.kms.model.v20160120.SetDeletionProtectionRequest;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static com.alibaba.nacos.client.aliyun.AliyunConst.KEY_ID;

public class ClientKeyKmsEncryptor extends KmsEncryptor{
    
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientKeyKmsEncryptor.class);
    
    private IAcsClient kmsClient;
    
    private String keyId;
    
    private Exception localInitException;
    
    private final Set<String> addedKeys = new HashSet<String>();
    
    private AsyncProcessor asyncProcessor;
    
    public ClientKeyKmsEncryptor(Properties properties)  {
        super(properties);
        keyId = properties.getProperty(KEY_ID, System.getProperty(KEY_ID, System.getenv(KEY_ID)));
        if (StringUtils.isBlank(keyId)) {
            String errorMsg = "keyId is not set up yet, unable to encrypt the configuration.";
            localInitException = new RuntimeException(errorMsg);
            LOGGER.error(AliyunConst.formatHelpMessage(errorMsg));
        } else {
            LOGGER.info("using keyId {}.", keyId);
        }
        try{
            kmsClient = createKmsV3Client(properties);
        }catch (ClientException e){
            localInitException = e;
        }
        
        if(localInitException == null){
            try {
                asyncProcessor = new AsyncProcessor();
            } catch (Exception e) {
                LOGGER.error("init async processor failed.", e);
            }
        }
    }
    
    public String encrypt(String plainText) throws Exception {
        AtomicReference<String> resultContent = new AtomicReference<>();
        final EncryptRequest encReq = new EncryptRequest();
        encReq.setProtocol(ProtocolType.HTTPS);
        encReq.setAcceptFormat(FormatType.XML);
        encReq.setMethod(MethodType.POST);
        encReq.setKeyId(keyId);
        encReq.setPlaintext(plainText);
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set( kmsClient.getAcsResponse(encReq).getCiphertextBlob());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            if (StringUtils.isBlank(resultContent.get())) {
                return false;
            }
            return true;
            
        }, defaultRetryTimes, defaultTimeoutMilliseconds);
        return resultContent.get();
    }
    
    @Override
    public String decrypt(String content) throws Exception {
        AtomicReference<String> resultContent = new AtomicReference<>();
        final DecryptRequest decReq = new DecryptRequest();
        decReq.setSysProtocol(ProtocolType.HTTPS);
        decReq.setSysMethod(MethodType.POST);
        decReq.setAcceptFormat(FormatType.XML);
        decReq.setCiphertextBlob(content);
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set(kmsClient.getAcsResponse(decReq).getPlaintext());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            if (StringUtils.isBlank(resultContent.get())) {
                return false;
            }
            return true;
        }, defaultRetryTimes, defaultTimeoutMilliseconds);
        return resultContent.get();
    }
    
    
    
    private IAcsClient createKmsV3Client(Properties properties) throws ClientException{
        Config config = new Config();
        config.setProtocol("https");
        IClientProfile profile = null;
        
        String kmsClientKeyContent = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY,
                System.getProperty(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, System.getenv(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY)));
        if (!StringUtils.isBlank(kmsClientKeyContent)) {
            LOGGER.info("using {}: {}.", AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, kmsClientKeyContent);
            config.setClientKeyContent(kmsClientKeyContent);
        } else {
            String errorMsg = null;
            LOGGER.info("{} is empty, will read from file.", AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY);
            String kmsClientKeyFilePath = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY,
                    System.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY, System.getenv(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY)));
            if (!StringUtils.isBlank(kmsClientKeyFilePath)) {
                String s = readFileToString(kmsClientKeyFilePath);
                if (!StringUtils.isBlank(s)) {
                    LOGGER.info("using kmsClientKeyFilePath: {}.", kmsClientKeyFilePath);
                    config.setClientKeyFile(kmsClientKeyFilePath);
                } else {
                    errorMsg = "both config from kmsClientKeyContent and kmsClientKeyFilePath is empty";
                }
            } else {
                errorMsg = "kmsClientKeyFilePath and kmsClientKeyContent are both empty";
            }
            if (!StringUtils.isBlank(errorMsg)) {
                localInitException = new RuntimeException(errorMsg);
                return null;
            }
        }
        
        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT,
                System.getProperty(AliyunConst.KMS_ENDPOINT, System.getenv(AliyunConst.KMS_ENDPOINT)));
        if (StringUtils.isBlank(kmsEndpoint)) {
            String errorMsg = String.format("%s is empty", AliyunConst.KMS_ENDPOINT);
            localInitException = new RuntimeException(errorMsg);
            return null;
        } else {
            LOGGER.info("using kmsEndpoint: {}.", kmsEndpoint);
            config.setEndpoint(kmsEndpoint);
        }
        
        String kmsPassword = properties.getProperty(AliyunConst.KMS_PASSWORD_KEY,
                System.getProperty(AliyunConst.KMS_PASSWORD_KEY, System.getenv(AliyunConst.KMS_PASSWORD_KEY)));
        if (StringUtils.isBlank(kmsPassword)) {
            String errorMsg = String.format("%s is empty", AliyunConst.KMS_PASSWORD_KEY);
            localInitException = new RuntimeException(errorMsg);
            return null;
        } else {
            LOGGER.info("using kmsPassword prefix: {}.", kmsPassword.substring(kmsPassword.length() / 8));
            config.setPassword(kmsPassword);
        }
        
        String kmsCaFileContent = properties.getProperty(AliyunConst.KMS_CA_FILE_CONTENT,
                System.getProperty(AliyunConst.KMS_CA_FILE_CONTENT, System.getenv(AliyunConst.KMS_CA_FILE_CONTENT)));
        if (!StringUtils.isBlank(kmsCaFileContent)) {
            LOGGER.info("using {}: {}.", AliyunConst.KMS_CA_FILE_CONTENT, kmsCaFileContent);
            config.setCa(kmsCaFileContent);
        } else {
            String errorMsg = null;
            LOGGER.info("{} is empty, will read from file.", AliyunConst.KMS_CA_FILE_CONTENT);
            String kmsCaFilePath = properties.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY,
                    System.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY, System.getenv(AliyunConst.KMS_CA_FILE_PATH_KEY)));
            if (!StringUtils.isBlank(kmsCaFilePath)) {
                config.setCaFilePath(kmsCaFilePath);
            } else {
                errorMsg = "kmsCaFilePath is empty";
                config.setCaFilePath(null);
            }
            if (!StringUtils.isBlank(errorMsg)) {
                LOGGER.warn(AliyunConst.formatHelpMessage(errorMsg));
                profile = DefaultProfile.getProfile(config.getRegionId(), "ak", "sk", "sts");
                HttpClientConfig httpClientConfig = HttpClientConfig.getDefault();
                httpClientConfig.setIgnoreSSLCerts(true);
                profile.setHttpClientConfig(httpClientConfig);
            }
        }
        
        if (profile == null) {
            return new KmsTransferAcsClient(config);
        }
        return new KmsTransferAcsClient(profile, config);
    }
    
    @Override
    public DataKey generateDataKey(String keySpec) throws Exception {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setAcceptFormat(FormatType.XML);
        generateDataKeyRequest.setKeyId(keyId);
        generateDataKeyRequest.setKeySpec(keySpec);
        AtomicReference<GenerateDataKeyResponse> resultContent = new AtomicReference<>();
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set(kmsClient.getAcsResponse(generateDataKeyRequest));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            if (resultContent.get() == null) {
                return false;
            }
            return true;
        }, defaultRetryTimes, defaultTimeoutMilliseconds);
        DataKey dataKey = new DataKey();
        dataKey.setEncryptedDataKey(resultContent.get().getCiphertextBlob());
        dataKey.setPlainDataKey(resultContent.get().getPlaintext());
        return dataKey;
    }
    
    @Override
    public void protectKeyId() {
        if (!addedKeys.contains(keyId)) {
            synchronized (addedKeys) {
                if (addedKeys.contains(keyId)) {
                    return;
                }
                addedKeys.add(keyId);
                asyncProcessor.addTack(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            if (kmsClient == null) {
                                LOGGER.error("kms client hasn't initiated.");
                                return;
                            }
                            DescribeKeyRequest describeKeyRequest = new DescribeKeyRequest();
                            describeKeyRequest.setKeyId(keyId);
                            try {
                                DescribeKeyResponse describeKeyResponse = kmsClient.getAcsResponse(describeKeyRequest);
                                if (describeKeyResponse.getKeyMetadata()!= null) {
                                    if (!"Enabled".equals(describeKeyResponse.getKeyMetadata().getKeyState())) {
                                        throw new RuntimeException("Key not available");
                                    }
                                    String arn = describeKeyResponse.getKeyMetadata().getArn();
                                    LOGGER.info("set deletion protection for keyId[{}], arn[{}]", keyId, arn);
                                    
                                    SetDeletionProtectionRequest setDeletionProtectionRequest = new SetDeletionProtectionRequest();
                                    setDeletionProtectionRequest.setProtectedResourceArn(arn);
                                    setDeletionProtectionRequest.setEnableDeletionProtection(true);
                                    setDeletionProtectionRequest.setDeletionProtectionDescription("key is used by mse");
                                    try {
                                        kmsClient.getAcsResponse(setDeletionProtectionRequest);
                                    } catch (ClientException e) {
                                        LOGGER.error("set deletion protect failed, keyId: {}.", keyId);
                                        throw e;
                                    }
                                } else {
                                    addedKeys.remove(keyId);
                                    LOGGER.warn("keyId meta is null, cannot set key protection");
                                }
                            } catch (ClientException e) {
                                LOGGER.error("describe key failed, keyId: {}.", keyId);
                                throw e;
                            }
                        } catch (Exception e) {
                            addedKeys.remove(keyId);
                            LOGGER.error("execute async task failed", e);
                        }
                        
                    }
                });
            }
        }
    }
    
    
    @Override
    public void checkIfKmsClientIsReady() throws Exception {
        if (kmsClient == null) {
            if (localInitException != null) {
                throw localInitException;
            } else {
                throw new RuntimeException("kms client isn't initialized. " +
                        "For more information, please check: " + AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
            }
        }
    }
    
    @Override
    public void checkKeyId() throws Exception {
        throwExceptionIfStringBlankWithErrorKey(keyId, "", "keyId is not set.", KEY_ID);
    }
    
    @Override
    public void close() throws IOException {
        asyncProcessor.shutdown();
    }
}
