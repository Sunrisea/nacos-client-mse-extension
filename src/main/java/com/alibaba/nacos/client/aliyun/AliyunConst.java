package com.alibaba.nacos.client.aliyun;

import java.nio.charset.StandardCharsets;

/**
 * the Const Values of Aliyun.
 *
 * @author luyanbo(RobberPhex)
 */
public class AliyunConst {
    
    public static final String GROUP = "group";
    
    public static final String DATA_ID = "dataId";
    
    public static final String CONTENT = "content";
    
    public static final String ENCRYPTED_DATA_KEY = "encryptedDataKey";
    
    public static final String CIPHER_PREFIX = "cipher-";
    
    public static final String CIPHER_KMS_AES_128_PREFIX = "cipher-kms-aes-128-";
    
    public static final String CIPHER_KMS_AES_256_PREFIX = "cipher-kms-aes-256-";
    
    public static final String KMS_KEY_SPEC_AES_128 = "AES_128";
    
    public static final String KMS_KEY_SPEC_AES_256 = "AES_256";
    
    public static final String KMS_ACCESS_KEY = "kmsAccessKey";
    
    public static final String KMS_SECRET_KEY = "kmsSecretKey";
    
    public static final String KMS_RAM_ROLE_NAME = "kmsRamRoleName";
    
    public static final String KMS_ROLE_ARN = "kmsRoleArn";
    
    public static final String KMS_POLICY = "kmsPolicy";
    
    public static final String KMS_ROLE_SESSION_EXPIRATION_SECONDS = "kmsRoleSessionExpiration";
    
    public static final String KMS_OIDC_PROVIDER_ARN = "kmsOidcProviderArn";
    
    public static final String KMS_ROLE_SESSION_NAME = "kmsRoleSessionName";
    
    public static final String KMS_OIDC_TOKEN_FILE_PATH = "kmsOidcTokenFilePath";
    
    public static final String KMS_SECURITY_TOKEN = "kmsSecurityToken";
    
    public static final String KMS_EXTENSION_ACCESS_KEY = "kmsExtensionAccessKey";
    
    public static final String KMS_EXTENSION_SECRET_KEY = "kmsExtensionSecretKey";
    
    public static final String KMS_CREDENTIALS_URI = "kmsCredentialsUri";
    
    public static final String ENCODE_UTF8 = StandardCharsets.UTF_8.displayName();
    
    public static final String ENCODE_UTF16 = StandardCharsets.UTF_16.displayName();
    
    public static final String KMS_ENDPOINT = "kmsEndpoint";

    public static final String KMS_VERSION_KEY = "kmsVersion";

    public static final String KMS_DEFAULT_KEY_ID_VALUE = "alias/acs/mse";
    
    public static final String REGION_ID = "regionId";
    
    public static final String KMS_REGION_ID = "kms_region_id";
    
    public static final String KEY_ID = "keyId";

    public static final String KMS_CLIENT_KEY_FILE_PATH_KEY = "kmsClientKeyFilePath";

    public static final String KMS_CLIENT_KEY_CONTENT_KEY = "kmsClientKeyContent";

    public static final String KMS_PASSWORD_KEY = "kmsPasswordKey";

    public static final String KMS_CA_FILE_PATH_KEY = "kmsCaFilePath";

    public static final String KMS_CA_FILE_CONTENT = "kmsCaFileContent";
    
    public static final String OPEN_SSL_KEY = "openSSL";

    public static final String MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL = "https://help.aliyun.com/zh/mse/user-guide/create-and-use-encrypted-configurations?spm=a2c4g.11186623.0.0.55587becdOW3jf";
    
    public static final String NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_SWITCH = "nacos.config.encryption.kms.local.cache.switch";
    
    public static final boolean DEFAULT_KMS_LOCAL_CACHE_SWITCH = true;
    
    public static final String NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_SIZE = "nacos.config.encryption.kms.local.cache.maxSize";
    
    public static final int DEFAULT_KMS_LOCAL_CACHE_MAX_SIZE = 1000;
    
    public static final String NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_AFTER_ACCESS_DURATION = "nacos.config.encryption.kms.local.cache.afterAccessDuration";
    
    public static final int DEFAULT_KMS_LOCAL_CACHE_AFTER_ACCESS_DURATION_SECONDS = 60 * 60;
    
    public static final String NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_AFTER_WRITE_DURATION = "nacos.config.encryption.kms.local.cache.afterWriteDuration";
    
    public static final int DEFAULT_KMS_LOCAL_CACHE_AFTER_WRITE_DURATION_SECONDS = 60 * 60 * 24;
    
    public static final String NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_TEST_MODE = "nacos.config.encryption.kms.local.cache.testMode";
    
    public static final String STRING_VALUE_BLANK_ERROR_MSG_FORMAT = "[config: %s] %s. %s is null or empty.";

    public static String formatHelpMessage(String errorMessage) {
        return String.format("%s, for more information, please check: %s",
                        errorMessage, AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
    }

    public enum KmsVersion {
        Kmsv1("v1.0"),
        Kmsv3("v3.0"),
        UNKNOWN_VERSION("unknown version");

        private String value;

        KmsVersion(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static KmsVersion fromValue(String value) {
            for (KmsVersion version : values()) {
                if (version.getValue().equals(value)) {
                    return version;
                }
            }
            return UNKNOWN_VERSION;
        }

    }
}
