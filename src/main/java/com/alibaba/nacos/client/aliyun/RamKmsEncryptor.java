package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.client.aliyun.provider.AccessKeyCredentialsProvider;
import com.alibaba.nacos.client.aliyun.provider.CredentialsUriKmsCredentialsProvider;
import com.alibaba.nacos.client.aliyun.provider.EcsRamRoleKmsCredentialsProvider;
import com.alibaba.nacos.client.aliyun.provider.KmsCredentialsProvider;
import com.alibaba.nacos.client.aliyun.provider.OidcRoleArnKmsCredentialsProvider;
import com.alibaba.nacos.client.aliyun.provider.RamRoleArnKmsCredentialsProvider;
import com.alibaba.nacos.client.aliyun.provider.StsTokenKmsCredentialsProvider;
import com.alibaba.nacos.common.utils.StringUtils;
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

import java.io.IOException;
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
    
    private final Set<KmsCredentialsProvider> credentialsProviders;
    
    public RamKmsEncryptor(Properties properties){
        super(properties);
        credentialsProviders = new HashSet<>();
        credentialsProviders.add(new AccessKeyCredentialsProvider());
        credentialsProviders.add(new StsTokenKmsCredentialsProvider());
        credentialsProviders.add(new RamRoleArnKmsCredentialsProvider());
        credentialsProviders.add(new EcsRamRoleKmsCredentialsProvider());
        credentialsProviders.add(new OidcRoleArnKmsCredentialsProvider());
        credentialsProviders.add(new CredentialsUriKmsCredentialsProvider());
        
        try{
            kmsClient = createClient(properties);
        }catch (Exception e){
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
        
        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT,
                System.getProperty(AliyunConst.KMS_ENDPOINT, System.getenv(AliyunConst.KMS_ENDPOINT)));
        LOGGER.info("using kmsEndpoint {}.", kmsEndpoint);
        
        Config config = new Config();
        runtimeOptions = new RuntimeOptions();
        
        boolean ifAuth = false;
        com.aliyun.credentials.models.Config credentialConfig = new com.aliyun.credentials.models.Config();
        for (KmsCredentialsProvider each : credentialsProviders) {
            if (each.matchProvider(properties)) {
                LOGGER.info("Match Kms credentials provider: {}", each.getClass().getName());
                credentialConfig = each.generateCredentialsConfig(properties);
                ifAuth = true;
                break;
            }
        }
        if(!ifAuth){
            String msg = "Ram Auth Information are not set up yet";
            LOGGER.error(msg);
            localInitException = new RuntimeException(msg);
            return null;
        }
        
        com.aliyun.credentials.Client credentialClient = new com.aliyun.credentials.Client(credentialConfig);
        config.setCredential(credentialClient);
        
        
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
            LOGGER.info("kmsEndpoint is not set up yet, KMS V1.0 mode");
            if (StringUtils.isBlank(kmsRegionId) && StringUtils.isBlank(regionId)) {
                String errorMsg = "KMS V1.0 mode, region is not set up yet";
                LOGGER.error(AliyunConst.formatHelpMessage(errorMsg));
                localInitException = new RuntimeException(errorMsg);
                return null;
            }
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
                try{
                    kmsCaFileContent = readFileToString(kmsCaFilePath);
                }catch (Exception e){
                    LOGGER.error("read kms ca file failed.", e);
                }
            }
        }
        
        if (!StringUtils.isBlank(kmsCaFileContent)) {
            LOGGER.info("using {}: {}.", AliyunConst.KMS_CA_FILE_CONTENT, kmsCaFileContent);
            config.setCa(kmsCaFileContent);
        } else {
            runtimeOptions.ignoreSSL=true;
        }
        
        String openSSL = properties.getProperty(AliyunConst.OPEN_SSL_KEY,
                System.getProperty(AliyunConst.OPEN_SSL_KEY, System.getenv(AliyunConst.OPEN_SSL_KEY)));
        if(!StringUtils.isBlank(openSSL)){
            if(openSSL.equalsIgnoreCase("false")){
                LOGGER.info("openSSL is set to false.");
                runtimeOptions.ignoreSSL = true;
            } else if (openSSL.equalsIgnoreCase("true")){
                LOGGER.info("ignoreSSL is set to true.");
                runtimeOptions.ignoreSSL = false;
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
    
    @Override
    public void close() throws IOException {
        asyncProcessor.shutdown();
    }
    
}
