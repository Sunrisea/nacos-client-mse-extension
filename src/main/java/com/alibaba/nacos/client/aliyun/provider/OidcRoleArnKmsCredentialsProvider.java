package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.client.aliyun.AliyunConst;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.common.utils.StringUtils;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public class OidcRoleArnKmsCredentialsProvider implements KmsCredentialsProvider{
    
    private String roleArn;
    
    private String roleSessionName;
    
    private String oidcProviderArn;
    
    private String oidcTokenFilePath;
    
    @Override
    public boolean matchProvider(Properties properties) {
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
        
        oidcProviderArn = properties.getProperty(AliyunConst.KMS_OIDC_PROVIDER_ARN,
                System.getProperty(AliyunConst.KMS_OIDC_PROVIDER_ARN, System.getenv(AliyunConst.KMS_OIDC_PROVIDER_ARN)));
        if(StringUtils.isBlank(oidcProviderArn)){
            oidcProviderArn = getNacosProperties(properties, ExtensionAuthPropertyKey.OIDC_PROVIDER_ARN);
        }
        
        oidcTokenFilePath = properties.getProperty(AliyunConst.KMS_OIDC_TOKEN_FILE_PATH,
                System.getProperty(AliyunConst.KMS_OIDC_TOKEN_FILE_PATH, System.getenv(AliyunConst.KMS_OIDC_TOKEN_FILE_PATH)));
        if(StringUtils.isBlank(oidcTokenFilePath)){
            oidcTokenFilePath = getNacosProperties(properties, ExtensionAuthPropertyKey.OIDC_TOKEN_FILE_PATH);
        }
        return StringUtils.isNotBlank(roleArn) && StringUtils.isNotBlank(roleSessionName)
                && StringUtils.isNotBlank(oidcProviderArn) && StringUtils.isNotBlank(oidcTokenFilePath);
        
    }
    
    @Override
    public Config generateCredentialsConfig(Properties properties) {
        Config credentialsConfig = new Config();
        credentialsConfig.setType("oidc_role_arn");
        credentialsConfig.setRoleArn(roleArn);
        credentialsConfig.setRoleSessionName(roleSessionName);
        credentialsConfig.setOidcProviderArn(oidcProviderArn);
        credentialsConfig.setOidcTokenFilePath(oidcTokenFilePath);
        String policy = properties.getProperty(AliyunConst.KMS_POLICY,
                System.getProperty(AliyunConst.KMS_POLICY, System.getenv(AliyunConst.KMS_POLICY)));
        if(StringUtils.isBlank(policy)){
            policy = getNacosProperties(properties, ExtensionAuthPropertyKey.POLICY);
        }
        if(StringUtils.isNotBlank(policy)){
            credentialsConfig.setPolicy(policy);
        }
        String roleSessionExpiration = properties.getProperty(AliyunConst.KMS_ROLE_SESSION_EXPIRATION_SECONDS,
                System.getProperty(AliyunConst.KMS_ROLE_SESSION_EXPIRATION_SECONDS, System.getenv(AliyunConst.KMS_ROLE_SESSION_EXPIRATION_SECONDS)));
        if(StringUtils.isBlank(roleSessionExpiration)){
            roleSessionExpiration = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_EXPIRATION);
        }
        if(StringUtils.isNotBlank(roleSessionExpiration)){
            credentialsConfig.setRoleSessionExpiration(Integer.parseInt(roleSessionExpiration));
        }
        return credentialsConfig;
    }
}
