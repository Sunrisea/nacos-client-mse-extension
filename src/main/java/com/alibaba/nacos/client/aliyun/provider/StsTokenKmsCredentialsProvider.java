package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.client.aliyun.AliyunConst;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.common.utils.StringUtils;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public class StsTokenKmsCredentialsProvider implements KmsCredentialsProvider{
    
    private String stsAccessKey;
    
    private String stsSecretKey;
    
    private String securityToken;
    
    @Override
    public boolean matchProvider(Properties properties) {
        stsAccessKey = properties.getProperty(AliyunConst.KMS_STS_AK,
                System.getProperty(AliyunConst.KMS_STS_AK, System.getenv(AliyunConst.KMS_STS_AK)));
        if(StringUtils.isBlank(stsAccessKey)){
            stsAccessKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_ID);
        }
        stsSecretKey = properties.getProperty(AliyunConst.KMS_STS_SECRET_KEY,
                System.getProperty(AliyunConst.KMS_STS_SECRET_KEY, System.getenv(AliyunConst.KMS_STS_SECRET_KEY)));
        if(StringUtils.isBlank(stsSecretKey)){
            stsSecretKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_SECRET);
        }
        
        securityToken = properties.getProperty(AliyunConst.KMS_SECURITY_TOKEN,
                System.getProperty(AliyunConst.KMS_SECURITY_TOKEN, System.getenv(AliyunConst.KMS_SECURITY_TOKEN)));
        if(StringUtils.isBlank(securityToken)){
            securityToken = getNacosProperties(properties, ExtensionAuthPropertyKey.SECURITY_TOKEN);
        }
        return StringUtils.isNotBlank(stsAccessKey) && StringUtils.isNotBlank(stsSecretKey) && StringUtils.isNotBlank(securityToken);
    }
    
    @Override
    public Config generateCredentialsConfig(Properties properties) {
        Config credentialConfig = new Config();
        credentialConfig.setType("sts");
        credentialConfig.setAccessKeyId(stsAccessKey);
        credentialConfig.setAccessKeySecret(stsSecretKey);
        credentialConfig.setSecurityToken(securityToken);
        return credentialConfig;
    }
}
