package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.DecryptRequest;
import com.aliyun.kms20160120.models.DecryptResponse;
import com.aliyun.kms20160120.models.DecryptResponseBody;
import com.aliyun.kms20160120.models.DescribeKeyRequest;
import com.aliyun.kms20160120.models.DescribeKeyResponse;
import com.aliyun.kms20160120.models.DescribeKeyResponseBody;
import com.aliyun.kms20160120.models.EncryptRequest;
import com.aliyun.kms20160120.models.EncryptResponse;
import com.aliyun.kms20160120.models.EncryptResponseBody;
import com.aliyun.kms20160120.models.GenerateDataKeyRequest;
import com.aliyun.kms20160120.models.GenerateDataKeyResponse;
import com.aliyun.kms20160120.models.GenerateDataKeyResponseBody;
import com.aliyun.kms20160120.models.SetDeletionProtectionRequest;
import com.aliyun.teautil.models.RuntimeOptions;
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
class RamKmsEncryptorTest {
    
    MockedConstruction<Client> mockClientConstruction;
    
    MockedStatic<AesUtils> mockAesUtils;
    
    @BeforeEach
    public void setUp() throws Exception {
        
        mockAesUtils = mockStatic(AesUtils.class);
        
        mockAesUtils.when(() -> AesUtils.decrypt("cipherText", "plainText", ENCODE_UTF8)).thenReturn("plainTextByAES");
        
        mockAesUtils.when(() -> AesUtils.encrypt("plainText", "plainKey", ENCODE_UTF8)).thenReturn("cipherTextByAES");
        EncryptResponse encryptResponse = new EncryptResponse();
        EncryptResponseBody body = new EncryptResponseBody();
        body.setCiphertextBlob("cipherText");
        encryptResponse.setBody(body);
        
        DecryptResponse decryptResponse = new DecryptResponse();
        DecryptResponseBody body1 = new DecryptResponseBody();
        decryptResponse.setBody(body1);
        body1.setPlaintext("plainText");
        
        DescribeKeyResponse describeKeyResponse = new DescribeKeyResponse();
        DescribeKeyResponseBody body2 = new DescribeKeyResponseBody();
        DescribeKeyResponseBody.DescribeKeyResponseBodyKeyMetadata keyMetadata = new DescribeKeyResponseBody.DescribeKeyResponseBodyKeyMetadata();
        keyMetadata.setKeyState("Enabled");
        body2.setKeyMetadata(keyMetadata);
        describeKeyResponse.setBody(body2);
        
        GenerateDataKeyResponse generateDataKeyResponse = new GenerateDataKeyResponse();
        GenerateDataKeyResponseBody body3 = new GenerateDataKeyResponseBody();
        body3.setPlaintext("plainKey");
        body3.setCiphertextBlob("cipherKey");
        generateDataKeyResponse.setBody(body3);
        
        mockClientConstruction = mockConstruction(Client.class, (mock, context) -> {
            when(mock.encryptWithOptions(any(EncryptRequest.class), any(RuntimeOptions.class))).thenReturn(
                    encryptResponse);
            when(mock.decryptWithOptions(any(DecryptRequest.class), any(RuntimeOptions.class))).thenReturn(
                    decryptResponse);
            when(mock.describeKeyWithOptions(any(DescribeKeyRequest.class), any(RuntimeOptions.class))).thenReturn(
                    describeKeyResponse);
            when(mock.setDeletionProtectionWithOptions(any(SetDeletionProtectionRequest.class),
                    any(RuntimeOptions.class))).thenReturn(null);
            when(mock.generateDataKeyWithOptions(any(GenerateDataKeyRequest.class),
                    any(RuntimeOptions.class))).thenReturn(generateDataKeyResponse);
        });
        
    }
    
    
    @AfterEach
    void tearDown() {
        mockClientConstruction.close();
        mockAesUtils.close();
    }
    
    @Test
    void testInit() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("accessKey", "accessKey");
        properties.setProperty("secretKey", "secretKey");
        properties.setProperty("regionId", "regionId");
        properties.setProperty(AliyunConst.KMS_ENDPOINT, "endPoint");
        
        ConfigRequest configRequest = new ConfigRequest();
        RamKmsEncryptor ramKmsEncryptor = new RamKmsEncryptor(properties);
        try {
            ramKmsEncryptor.encrypt(configRequest);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("keyId is null or empty"));
        }
        
        Properties properties1 = new Properties();
        properties1.setProperty("accessKey", "accessKey");
        //        properties1.setProperty("secretKey","secretKey");
        properties1.setProperty("regionId", "regionId");
        
        RamKmsEncryptor ramKmsEncryptor1 = new RamKmsEncryptor(properties1);
        try {
            ramKmsEncryptor1.encrypt(configRequest);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("ramRoleName or accessKey/secretKey are not set up yet"));
        }
        
        Properties properties2 = new Properties();
        properties2.setProperty("ramRoleName", "ramRoleName");
        properties2.setProperty("regionId", "regionId");
        RamKmsEncryptor ramKmsEncryptor2 = new RamKmsEncryptor(properties2);
        Field field = RamKmsEncryptor.class.getDeclaredField("kmsClient");
        field.setAccessible(true);
        assertNotNull(field.get(ramKmsEncryptor2));
    }
    
    @Test
    void encryptAndDecryptTest() throws Exception {
        ConfigRequest configRequest = new ConfigRequest();
        configRequest.setDataId(CIPHER_KMS_AES_256_PREFIX + "dataId");
        configRequest.setGroup("DEFAULT_GROUP");
        configRequest.setContent("plainText");
        
        Properties properties = new Properties();
        properties.setProperty("ramRoleName", "ramRoleName");
        properties.setProperty("regionId", "regionId");
        RamKmsEncryptor ramKmsEncryptor = new RamKmsEncryptor(properties);
        assertEquals(ramKmsEncryptor.encrypt(configRequest), "cipherTextByAES");
        
        configRequest.setDataId(CIPHER_PREFIX + "dataId");
        assertEquals(ramKmsEncryptor.encrypt(configRequest), "cipherText");
        
        ConfigResponse configResponse = new ConfigResponse();
        configResponse.setContent("cipherText");
        configResponse.setEncryptedDataKey("encryptedDataKey");
        configResponse.setDataId(CIPHER_KMS_AES_256_PREFIX + "dataId");
        configResponse.setGroup("DEFAULT_GROUP");
        assertEquals(ramKmsEncryptor.decrypt(configResponse), "plainTextByAES");
        
        configResponse.setDataId(CIPHER_PREFIX + "dataId");
        assertEquals(ramKmsEncryptor.decrypt(configResponse), "plainText");
    }
}