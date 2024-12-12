package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.client.aliyun.AliyunConst;
import com.alibaba.nacos.common.utils.StringUtils;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public class AccessKeyCredentialsProvider implements KmsCredentialsProvider{
    
    private String accessKey;
    
    private String secretKey;
    
    @Override
    public boolean matchProvider(Properties properties) {
        accessKey = properties.getProperty(AliyunConst.KMS_ACCESS_KEY,
                System.getProperty(AliyunConst.KMS_ACCESS_KEY, System.getenv(AliyunConst.KMS_ACCESS_KEY)));
        if(StringUtils.isBlank(accessKey)){
            accessKey = properties.getProperty(PropertyKeyConst.ACCESS_KEY,
                    System.getProperty(PropertyKeyConst.ACCESS_KEY, System.getenv(PropertyKeyConst.ACCESS_KEY)));
        }
        secretKey = properties.getProperty(AliyunConst.KMS_SECRET_KEY,
                System.getProperty(AliyunConst.KMS_SECRET_KEY, System.getenv(AliyunConst.KMS_SECRET_KEY)));
        if(StringUtils.isBlank(secretKey)){
            secretKey = properties.getProperty(PropertyKeyConst.SECRET_KEY,
                    System.getProperty(PropertyKeyConst.SECRET_KEY, System.getenv(PropertyKeyConst.SECRET_KEY)));
        }
        return !StringUtils.isBlank(accessKey) && !StringUtils.isBlank(secretKey);
    }
    
    @Override
    public Config generateCredentialsConfig(Properties properties) {
        Config credentialConfig = new Config();
        credentialConfig.setType("access_key");
        credentialConfig.setAccessKeyId(accessKey);
        credentialConfig.setAccessKeySecret(secretKey);
        return credentialConfig;
    }
}
