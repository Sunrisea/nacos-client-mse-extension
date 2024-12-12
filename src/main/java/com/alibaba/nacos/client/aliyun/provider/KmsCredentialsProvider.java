package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public interface KmsCredentialsProvider {
    
    boolean matchProvider(Properties properties);
    
    Config generateCredentialsConfig(Properties properties);
    
    default String getNacosProperties(Properties properties, ExtensionAuthPropertyKey key) {
        String result = properties.getProperty(key.getKey());
        if (StringUtils.isEmpty(result)) {
            result = properties.getProperty(key.getEnvKey());
        }
        // For Adapt 2.1.X, in 2.1.X version, NacosClientProperties not finished all replaced, so properties don't include env.
        if (StringUtils.isEmpty(result)) {
            result = System.getenv(key.getEnvKey());
        }
        return result;
    }
    
}
