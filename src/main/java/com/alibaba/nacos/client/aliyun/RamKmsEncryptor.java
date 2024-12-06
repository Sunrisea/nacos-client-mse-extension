package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.DecryptRequest;
import com.aliyun.kms20160120.models.DescribeKeyRequest;
import com.aliyun.kms20160120.models.DescribeKeyResponse;
import com.aliyun.kms20160120.models.EncryptRequest;
import com.aliyun.kms20160120.models.GenerateDataKeyRequest;
import com.aliyun.kms20160120.models.GenerateDataKeyResponseBody;
import com.aliyun.kms20160120.models.SetDeletionProtectionRequest;
import com.aliyun.teaopenapi.models.Config;
import com.aliyun.teautil.models.RuntimeOptions;
import com.aliyuncs.exceptions.ClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static com.alibaba.nacos.client.aliyun.AliyunConst.KEY_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KMS_REGION_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.REGION_ID;

public class RamKmsEncryptor extends KmsEncryptor{
    
    private static final Logger LOGGER = LoggerFactory.getLogger(RamKmsEncryptor.class);
    
    private Client kmsClient;
    
    private String keyId;
    
    private RuntimeOptions runtimeOptions;
    
    private Exception localInitException;
    
    private final Set<String> addedKeys = new HashSet<String>();
    
    private AsyncProcessor asyncProcessor;
    
    public RamKmsEncryptor(Properties properties){
        super(properties);
        try{
            kmsClient = createClient(properties);
        }catch (Exception e){
            localInitException = e;
        }
        
        try {
            asyncProcessor = new AsyncProcessor();
        } catch (Exception e) {
            LOGGER.error("init async processor failed.", e);
        }
    }
    
    private Client createClient(Properties properties) throws Exception {
        String regionId = properties.getProperty(REGION_ID, System.getProperty(REGION_ID, System.getenv(REGION_ID)));
        String kmsRegionId = properties.getProperty(KMS_REGION_ID, System.getProperty(KMS_REGION_ID, System.getenv(KMS_REGION_ID)));
        if (StringUtils.isBlank(regionId)) {
            regionId = kmsRegionId;
        }
        LOGGER.info("using regionId {}.", regionId);
        if (StringUtils.isBlank(kmsRegionId)) {
            kmsRegionId = regionId;
        }
        LOGGER.info("using kms regionId {}.", kmsRegionId);
        
        if (StringUtils.isBlank(kmsRegionId) && StringUtils.isBlank(regionId)) {
            String errorMsg = "region is not set up yet";
            LOGGER.error(AliyunConst.formatHelpMessage(errorMsg));
            localInitException = new RuntimeException(errorMsg);
            return null;
        }
        
        String ramRoleName= properties.getProperty(PropertyKeyConst.RAM_ROLE_NAME,
                System.getProperty(PropertyKeyConst.RAM_ROLE_NAME, System.getenv(PropertyKeyConst.RAM_ROLE_NAME)));
        LOGGER.info("using ramRoleName {}.", ramRoleName);
        
        String accessKey = properties.getProperty(PropertyKeyConst.ACCESS_KEY,
                System.getProperty(PropertyKeyConst.ACCESS_KEY, System.getenv(PropertyKeyConst.ACCESS_KEY)));
        LOGGER.info("using accessKey {}.", accessKey);
        
        String secretKey = properties.getProperty(PropertyKeyConst.SECRET_KEY,
                System.getProperty(PropertyKeyConst.SECRET_KEY, System.getenv(PropertyKeyConst.SECRET_KEY)));
        
        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT,
                System.getProperty(AliyunConst.KMS_ENDPOINT, System.getenv(AliyunConst.KMS_ENDPOINT)));
        LOGGER.info("using kmsEndpoint {}.", kmsEndpoint);
        
        Config config = new Config();
        runtimeOptions = new RuntimeOptions();
        
        if(StringUtils.isBlank(ramRoleName)&&(StringUtils.isBlank(accessKey)||StringUtils.isBlank(secretKey))){
            String msg = "ramRoleName or accessKey/secretKey are not set up yet";
            LOGGER.error(msg);
            localInitException = new RuntimeException(msg);
            return null;
        }
        
        if(StringUtils.isBlank(accessKey)||StringUtils.isBlank(secretKey)){
            com.aliyun.credentials.models.Config credentialConfig = new com.aliyun.credentials.models.Config();
            credentialConfig.setType("ecs_ram_role");
            if(!StringUtils.isBlank(ramRoleName)){
                credentialConfig.setRoleName(ramRoleName);
            }
            com.aliyun.credentials.Client credentialClient = new com.aliyun.credentials.Client(credentialConfig);
            config.setCredential(credentialClient);
        } else {
            config.setAccessKeyId(accessKey);
            config.setAccessKeySecret(secretKey);
        }
        
        config.setRegionId(kmsRegionId);
        if(!StringUtils.isBlank(kmsEndpoint)){
            config.setEndpoint(kmsEndpoint);
            keyId = properties.getProperty(KEY_ID, System.getProperty(KEY_ID, System.getenv(KEY_ID)));
            if(StringUtils.isBlank(keyId)){
                String msg = "keyId is not set up yet, unable to encrypt the configuration.";
                LOGGER.error(msg);
            }else{
                LOGGER.info("using keyId {}.", keyId);
            }
        }else{
            LOGGER.info("kmsEndpoint is not set up yet, KMS V1.0 module");
            keyId = AliyunConst.KMS_DEFAULT_KEY_ID_VALUE;
            return new Client(config);
        }
        
        String kmsCaFileContent = properties.getProperty(AliyunConst.KMS_CA_FILE_CONTENT,
                System.getProperty(AliyunConst.KMS_CA_FILE_CONTENT, System.getenv(AliyunConst.KMS_CA_FILE_CONTENT)));
        if(StringUtils.isBlank(kmsCaFileContent)){
            String kmsCaFilePath = properties.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY,
                    System.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY,
                            System.getenv(AliyunConst.KMS_CA_FILE_PATH_KEY)));
            if(!StringUtils.isBlank(kmsCaFilePath)){
                kmsCaFileContent = readFileToString(kmsCaFilePath);
            }
        }
        
        if (!StringUtils.isBlank(kmsCaFileContent)) {
            LOGGER.info("using {}: {}.", AliyunConst.KMS_CA_FILE_CONTENT, kmsCaFileContent);
            config.setCa(kmsCaFileContent);
        } else {
            String ignoreSSL = properties.getProperty(AliyunConst.IGNORE_SSL_KEY,
                    System.getProperty(AliyunConst.IGNORE_SSL_KEY, System.getenv(AliyunConst.IGNORE_SSL_KEY)));
            if(!StringUtils.isBlank(ignoreSSL)&&ignoreSSL.equalsIgnoreCase("true")){
                LOGGER.info("ignoreSSL is set to true.");
                runtimeOptions.ignoreSSL = true;
            }
        }
        return new Client(config);
    }
    
    @Override
    public String encrypt(String plainText) throws Exception {
        AtomicReference<String> resultContent = new AtomicReference<>();
        final EncryptRequest encReq = new EncryptRequest();
        encReq.setKeyId(keyId);
        encReq.setPlaintext(plainText);
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set( kmsClient.encryptWithOptions(encReq, runtimeOptions).getBody().getCiphertextBlob());
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
    public String decrypt(String encryptedContent) throws Exception {
        AtomicReference<String> resultContent = new AtomicReference<>();
        final DecryptRequest decReq = new DecryptRequest();
        decReq.setCiphertextBlob(encryptedContent);
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set(kmsClient.decryptWithOptions(decReq, runtimeOptions).getBody().getPlaintext());
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
                                DescribeKeyResponse describeKeyResponse = kmsClient.describeKeyWithOptions(describeKeyRequest, runtimeOptions);
                                if (describeKeyResponse.getBody().getKeyMetadata()!= null) {
                                    if (!"Enabled".equals(describeKeyResponse.getBody().getKeyMetadata().getKeyState())) {
                                        throw new RuntimeException("Key not available");
                                    }
                                    String arn = describeKeyResponse.getBody().getKeyMetadata().getArn();
                                    LOGGER.info("set deletion protection for keyId[{}], arn[{}]", keyId, arn);
                                    
                                    SetDeletionProtectionRequest setDeletionProtectionRequest = new SetDeletionProtectionRequest();
                                    setDeletionProtectionRequest.setProtectedResourceArn(arn);
                                    setDeletionProtectionRequest.setEnableDeletionProtection(true);
                                    setDeletionProtectionRequest.setDeletionProtectionDescription("key is used by mse");
                                    try {
                                        kmsClient.setDeletionProtectionWithOptions(setDeletionProtectionRequest, runtimeOptions);
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
    public DataKey generateDataKey(String keySpec) throws Exception {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setKeyId(keyId);
        generateDataKeyRequest.setKeySpec(keySpec);
        AtomicReference<GenerateDataKeyResponseBody> resultContent = new AtomicReference<>();
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set(kmsClient.generateDataKeyWithOptions(generateDataKeyRequest,runtimeOptions).getBody());
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
    public void checkKeyId() throws Exception {
        throwExceptionIfStringBlankWithErrorKey(keyId, "", "keyId is not set.", KEY_ID);
    }
    
}
