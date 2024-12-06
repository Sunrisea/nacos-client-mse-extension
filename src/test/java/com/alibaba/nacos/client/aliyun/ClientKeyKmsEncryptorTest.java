package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import com.aliyun.kms.KmsTransferAcsClient;
import com.aliyuncs.kms.model.v20160120.DecryptRequest;
import com.aliyuncs.kms.model.v20160120.DecryptResponse;
import com.aliyuncs.kms.model.v20160120.DescribeKeyRequest;
import com.aliyuncs.kms.model.v20160120.DescribeKeyResponse;
import com.aliyuncs.kms.model.v20160120.EncryptRequest;
import com.aliyuncs.kms.model.v20160120.EncryptResponse;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import com.aliyuncs.kms.model.v20160120.SetDeletionProtectionRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.Properties;

import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_256_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.ENCODE_UTF8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class ClientKeyKmsEncryptorTest {
    
    MockedConstruction<KmsTransferAcsClient> mockClientConstruction;
    
    MockedStatic<AesUtils> mockAesUtils;
    
    @BeforeEach
    public void setUp() throws Exception {
        
        mockAesUtils = mockStatic(AesUtils.class);
        
        mockAesUtils.when(()->AesUtils.decrypt("cipherText","plainText",ENCODE_UTF8))
                .thenReturn("plainTextByAES");
        
        mockAesUtils.when(()->AesUtils.encrypt("plainText","plainKey",ENCODE_UTF8))
                .thenReturn("cipherTextByAES");
        
        GenerateDataKeyResponse generateDataKeyResponse = new GenerateDataKeyResponse();
        generateDataKeyResponse.setPlaintext("plainKey");
        generateDataKeyResponse.setCiphertextBlob("cipherKey");
        
        DescribeKeyResponse describeKeyResponse = new DescribeKeyResponse();
        DescribeKeyResponse.KeyMetadata keyMetadata = new DescribeKeyResponse.KeyMetadata();
        keyMetadata.setKeyState("Enabled");
        describeKeyResponse.setKeyMetadata(keyMetadata);
        
        DecryptResponse decryptResponse = new DecryptResponse();
        decryptResponse.setPlaintext("plainText");
        
        EncryptResponse encryptResponse = new EncryptResponse();
        encryptResponse.setCiphertextBlob("cipherText");
        
        mockClientConstruction = mockConstruction(KmsTransferAcsClient.class,(mock,context)->{
            when(mock.getAcsResponse(any(DescribeKeyRequest.class))).thenReturn(describeKeyResponse);
            when(mock.getAcsResponse(any(GenerateDataKeyRequest.class))).thenReturn(generateDataKeyResponse);
            when(mock.getAcsResponse(any(SetDeletionProtectionRequest.class))).thenReturn(null);
            when(mock.getAcsResponse(any(DecryptRequest.class))).thenReturn(decryptResponse);
            when(mock.getAcsResponse(any(EncryptRequest.class))).thenReturn(encryptResponse);
        });
    }
    
    @AfterEach
    public void tearDown() throws Exception {
        mockClientConstruction.close();
        mockAesUtils.close();
    }
    
    
    @Test
    void testInit() throws Exception {
        Properties properties = new Properties();
        properties.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "clientKeyContent");
        properties.put(AliyunConst.KMS_ENDPOINT,"endPoint");
//        properties.put(AliyunConst.KEY_ID,"keyId");
        properties.put(AliyunConst.KMS_PASSWORD_KEY,"password");
        properties.put(AliyunConst.KMS_CA_FILE_CONTENT,"caFileContent");
        ClientKeyKmsEncryptor clientKeyKmsEncryptor1 = new ClientKeyKmsEncryptor(properties);
        
        ConfigRequest configRequest = new ConfigRequest();
        try{
            clientKeyKmsEncryptor1.encrypt(configRequest);
        }catch (Exception e){
            assertTrue(e.getMessage().contains("keyId is null or empty"));
        }
        
        Properties properties2 = new Properties();
//        properties2.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "clientKeyContent");
        properties2.put(AliyunConst.KMS_ENDPOINT,"endPoint");
        properties2.put(AliyunConst.KEY_ID,"keyId");
        properties2.put(AliyunConst.KMS_PASSWORD_KEY,"password");
        properties2.put(AliyunConst.KMS_CA_FILE_CONTENT,"caFileContent");
        ClientKeyKmsEncryptor clientKeyKmsEncryptor2 = new ClientKeyKmsEncryptor(properties2);
        try{
            clientKeyKmsEncryptor2.encrypt(configRequest);
        }catch (Exception e){
            assertTrue(e.getMessage().contains( "kmsClientKeyFilePath and kmsClientKeyContent are both empty"));
        }
        
        Properties properties3 = new Properties();
        properties3.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "clientKeyContent");
//        properties3.put(AliyunConst.KMS_ENDPOINT,"endPoint");
        properties3.put(AliyunConst.KEY_ID,"keyId");
        properties3.put(AliyunConst.KMS_PASSWORD_KEY,"password");
        properties3.put(AliyunConst.KMS_CA_FILE_CONTENT,"caFileContent");
        ClientKeyKmsEncryptor clientKeyKmsEncryptor3 = new ClientKeyKmsEncryptor(properties3);
        try{
            clientKeyKmsEncryptor3.encrypt(configRequest);
        } catch (Exception e){
            assertTrue(e.getMessage().contains("kmsEndpoint is empty"));
        }
        
        Properties properties4 = new Properties();
        properties4.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "clientKeyContent");
        properties4.put(AliyunConst.KMS_ENDPOINT,"endPoint");
        properties4.put(AliyunConst.KEY_ID,"keyId");
//        properties4.put(AliyunConst.KMS_PASSWORD_KEY,"password");
        properties4.put(AliyunConst.KMS_CA_FILE_CONTENT,"caFileContent");
        ClientKeyKmsEncryptor clientKeyKmsEncryptor4 = new ClientKeyKmsEncryptor(properties4);
        try{
            clientKeyKmsEncryptor4.encrypt(configRequest);
        } catch (Exception e){
            assertTrue(e.getMessage().contains("kmsPasswordKey is empty"));
        }
        
        Properties properties5 = new Properties();
        properties5.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "clientKeyContent");
        properties5.put(AliyunConst.KMS_ENDPOINT,"endPoint");
        properties5.put(AliyunConst.KEY_ID,"keyId");
        properties5.put(AliyunConst.KMS_PASSWORD_KEY,"password");
        properties5.put(AliyunConst.KMS_CA_FILE_CONTENT,"caFileContent");
        ClientKeyKmsEncryptor clientKeyKmsEncryptor5 = new ClientKeyKmsEncryptor(properties5);
        
        Field field = ClientKeyKmsEncryptor.class.getDeclaredField("kmsClient");
        field.setAccessible(true);
        assertNotNull(field.get(clientKeyKmsEncryptor5));
        
    }
    
    @Test
    void encryptAndDecryptTest() throws Exception {
        ConfigRequest configRequest = new ConfigRequest();
        configRequest.setDataId(CIPHER_KMS_AES_256_PREFIX+"dataId");
        configRequest.setGroup("DEFAULT_GROUP");
        configRequest.setContent("plainText");
        
        Properties properties = new Properties();
        properties.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "clientKeyContent");
        properties.put(AliyunConst.KMS_ENDPOINT,"endPoint");
                properties.put(AliyunConst.KEY_ID,"keyId");
        properties.put(AliyunConst.KMS_PASSWORD_KEY,"password");
        properties.put(AliyunConst.KMS_CA_FILE_CONTENT,"caFileContent");
        ClientKeyKmsEncryptor clientKeyKmsEncryptor = new ClientKeyKmsEncryptor(properties);
        assertEquals(clientKeyKmsEncryptor.encrypt(configRequest),"cipherTextByAES");
        
        configRequest.setDataId(CIPHER_PREFIX+"dataId");
        assertEquals(clientKeyKmsEncryptor.encrypt(configRequest),"cipherText");
        
        ConfigResponse configResponse = new ConfigResponse();
        configResponse.setContent("cipherText");
        configResponse.setEncryptedDataKey("encryptedDataKey");
        configResponse.setDataId(CIPHER_KMS_AES_256_PREFIX+"dataId");
        configResponse.setGroup("DEFAULT_GROUP");
        assertEquals(clientKeyKmsEncryptor.decrypt(configResponse),"plainTextByAES");
        
        configResponse.setDataId(CIPHER_PREFIX+"dataId");
        assertEquals(clientKeyKmsEncryptor.decrypt(configResponse),"plainText");
    }
}