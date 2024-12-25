package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.client.aliyun.AliyunConst;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.common.utils.StringUtils;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public class RamRoleArnKmsCredentialsProvider implements KmsCredentialsProvider{
    
    private String accessKey;
    
    private String secretKey;
    
    private String roleArn;
    
    private String roleSessionName;
    
    @Override
    public boolean matchProvider(Properties properties) {
        accessKey = properties.getProperty(AliyunConst.KMS_EXTENSION_ACCESS_KEY,
                System.getProperty(AliyunConst.KMS_EXTENSION_ACCESS_KEY, System.getenv(AliyunConst.KMS_EXTENSION_ACCESS_KEY)));
        if(StringUtils.isBlank(accessKey)){
            accessKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_ID);
        }
        
        secretKey = properties.getProperty(AliyunConst.KMS_EXTENSION_SECRET_KEY,
                System.getProperty(AliyunConst.KMS_EXTENSION_SECRET_KEY, System.getenv(AliyunConst.KMS_EXTENSION_SECRET_KEY)));
        if(StringUtils.isBlank(secretKey)){
            secretKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_SECRET);
        }
        
        roleArn = properties.getProperty(AliyunConst.KMS_ROLE_ARN,
                System.getProperty(AliyunConst.KMS_ROLE_ARN, System.getenv(AliyunConst.KMS_ROLE_ARN)));
        if(StringUtils.isBlank(roleArn)){
            roleArn = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_ARN);
        }
        
        roleSessionName = properties.getProperty(AliyunConst.KMS_ROLE_SESSION_NAME,
                System.getProperty(AliyunConst.KMS_ROLE_SESSION_NAME, System.getenv(AliyunConst.KMS_ROLE_SESSION_NAME)));
        if(StringUtils.isBlank(roleSessionName)){
            roleSessionName = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_NAME);
        }
        
        return StringUtils.isNotBlank(accessKey) && StringUtils.isNotBlank(secretKey) && StringUtils.isNotBlank(roleArn)
                && StringUtils.isNotBlank(roleSessionName);
    }
    
    @Override
    public Config generateCredentialsConfig(Properties properties) {
        Config config = new Config();
        config.setType("ram_role_arn");
        config.setAccessKeyId(accessKey);
        config.setAccessKeySecret(secretKey);
        config.setRoleArn(roleArn);
        config.setRoleSessionName(roleSessionName);
        String policy = properties.getProperty(AliyunConst.KMS_POLICY,
                System.getProperty(AliyunConst.KMS_POLICY, System.getenv(AliyunConst.KMS_POLICY)));
        if(StringUtils.isBlank(policy)){
            policy = getNacosProperties(properties, ExtensionAuthPropertyKey.POLICY);
        }
        if(StringUtils.isNotBlank(policy)){
            config.setPolicy(policy);
        }
        String roleSessionExpiration = properties.getProperty(AliyunConst.KMS_ROLE_SESSION_EXPIRATION_SECONDS,
                System.getProperty(AliyunConst.KMS_ROLE_SESSION_EXPIRATION_SECONDS, System.getenv(AliyunConst.KMS_ROLE_SESSION_EXPIRATION_SECONDS)));
        if(StringUtils.isBlank(roleSessionExpiration)){
            roleSessionExpiration = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_EXPIRATION);
        }
        if(StringUtils.isNotBlank(roleSessionExpiration)){
            config.setRoleSessionExpiration(Integer.parseInt(roleSessionExpiration));
        }
        return config;
    }
}
