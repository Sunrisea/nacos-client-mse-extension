package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.client.aliyun.AliyunConst;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.common.utils.StringUtils;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public class CredentialsUriKmsCredentialsProvider implements KmsCredentialsProvider{
    
    String credentialsUri;
    
    @Override
    public boolean matchProvider(Properties properties) {
        credentialsUri = properties.getProperty(AliyunConst.KMS_CREDENTIALS_URI,
                System.getProperty(AliyunConst.KMS_CREDENTIALS_URI,System.getenv(AliyunConst.KMS_CREDENTIALS_URI)));
        if(StringUtils.isBlank(credentialsUri)){
            credentialsUri = getNacosProperties(properties, ExtensionAuthPropertyKey.CREDENTIALS_URI);
        }
        
        return StringUtils.isNotBlank(credentialsUri);
    }
    
    @Override
    public Config generateCredentialsConfig(Properties properties) {
        Config config = new Config();
        config.setType("credentials_uri");
        config.setCredentialsUri(credentialsUri);
        return config;
    }
}
