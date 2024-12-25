package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.config.filter.IConfigFilterChain;
import com.alibaba.nacos.api.config.filter.IConfigRequest;
import com.alibaba.nacos.api.config.filter.IConfigResponse;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AliyunConfigFilterTest {
    
    MockedConstruction<RamKmsEncryptor> ramKmsEncryptorMockedConstruction;
    
    @Mock
    IConfigFilterChain chain;
    
    @BeforeEach
    void setUp() {
        ramKmsEncryptorMockedConstruction = mockConstruction(RamKmsEncryptor.class,(mock,contexnt)->{
            when(mock.encrypt(any(IConfigRequest.class))).thenReturn("encryptedContext");
            when(mock.decrypt(any(IConfigResponse.class))).thenReturn("plainText");
        });
    }
    
    @AfterEach
    void tearDown() {
        ramKmsEncryptorMockedConstruction.close();
    }
    
    @Test
    void init() throws NoSuchFieldException, IllegalAccessException {
        Properties properties_1 = new Properties();
        properties_1.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "test");
        AliyunConfigFilter aliyunConfigFilter_1 = new AliyunConfigFilter();
        aliyunConfigFilter_1.init(properties_1);
        Field field = aliyunConfigFilter_1.getClass().getDeclaredField("kmsEncryptor");
        field.setAccessible(true);
        KmsEncryptor kmsEncryptor = (KmsEncryptor) field.get(aliyunConfigFilter_1);
        assertTrue(kmsEncryptor instanceof ClientKeyKmsEncryptor);
        
        Properties properties_2 = new Properties();
        AliyunConfigFilter aliyunConfigFilter_2 = new AliyunConfigFilter();
        aliyunConfigFilter_2.init(properties_2);
        KmsEncryptor kmsEncryptor_2 = (KmsEncryptor) field.get(aliyunConfigFilter_2);
        assertTrue(kmsEncryptor_2 instanceof RamKmsEncryptor);
    }
    
    @Test
    void doFilter() throws NacosException {
        
        Properties properties_2 = new Properties();
        AliyunConfigFilter aliyunConfigFilter_2 = new AliyunConfigFilter();
        aliyunConfigFilter_2.init(properties_2);
        
        ConfigRequest request = new ConfigRequest();
        request.putParameter("dataId", "cipher-test");
        request.putParameter("content","test-context");
        
        ConfigResponse response = new ConfigResponse();
        response.putParameter("dataId", "cipher-test");
        response.putParameter("content","test-context");
        doNothing().when(chain).doFilter(any(),any());
        aliyunConfigFilter_2.doFilter(request, response, chain);
        
        assertEquals("encryptedContext",request.getParameter("content"));
        assertEquals("plainText",response.getParameter("content"));
    }
    
    @Test
    void getOrder() {
        Properties properties = new Properties();
        AliyunConfigFilter aliyunConfigFilter = new AliyunConfigFilter();
        aliyunConfigFilter.init(properties);
        assertEquals(1, aliyunConfigFilter.getOrder());
    }
    
    @Test
    void getFilterName() {
        Properties properties = new Properties();
        AliyunConfigFilter aliyunConfigFilter = new AliyunConfigFilter();
        aliyunConfigFilter.init(properties);
        assertEquals("com.alibaba.nacos.client.aliyun.AliyunConfigFilter", aliyunConfigFilter.getFilterName());
    }
}