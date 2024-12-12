package com.alibaba.nacos.client.aliyun.provider;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.client.aliyun.AliyunConst;
import com.alibaba.nacos.common.utils.StringUtils;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

public class EcsRamRoleKmsCredentialsProvider implements KmsCredentialsProvider{
    
    private String ramRoleName;
    
    @Override
    public boolean matchProvider(Properties properties) {
        ramRoleName = properties.getProperty(AliyunConst.KMS_RAM_ROLE_NAME,
                System.getProperty(AliyunConst.KMS_RAM_ROLE_NAME, System.getenv(AliyunConst.KMS_RAM_ROLE_NAME)));
        if(StringUtils.isBlank(ramRoleName)){
            ramRoleName= properties.getProperty(PropertyKeyConst.RAM_ROLE_NAME,
                    System.getProperty(PropertyKeyConst.RAM_ROLE_NAME, System.getenv(PropertyKeyConst.RAM_ROLE_NAME)));
        }
        return !StringUtils.isBlank(ramRoleName);
    }
    
    @Override
    public Config generateCredentialsConfig(Properties properties) {
        Config credentialConfig = new Config();
        credentialConfig.setType("ecs_ram_role");
        credentialConfig.setRoleName(ramRoleName);
        return credentialConfig;
    }
}
