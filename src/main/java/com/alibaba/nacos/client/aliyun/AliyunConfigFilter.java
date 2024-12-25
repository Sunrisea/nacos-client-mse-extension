package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.config.filter.AbstractConfigFilter;
import com.alibaba.nacos.api.config.filter.IConfigFilterChain;
import com.alibaba.nacos.api.config.filter.IConfigRequest;
import com.alibaba.nacos.api.config.filter.IConfigResponse;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyuncs.exceptions.ClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Properties;

import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CONTENT;
import static com.alibaba.nacos.client.aliyun.AliyunConst.DATA_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.GROUP;

/**
 * the IConfigFilter of Aliyun.
 *
 * @author luyanbo(RobberPhex)
 */
public class AliyunConfigFilter extends AbstractConfigFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AliyunConfigFilter.class);
    
    private KmsEncryptor kmsEncryptor;

    @Override
    public void init(Properties properties) {
        LOGGER.info("init ConfigFilter: {}, for more information, please check: {}",
                this.getFilterName(), AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
        
        String kmsClientKeyContent = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY,
                System.getProperty(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, System.getenv(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY)));
        String kmsClientKeyFilePath = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY,
                System.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY, System.getenv(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY)));
        
        if(!StringUtils.isBlank(kmsClientKeyContent)||!StringUtils.isBlank(kmsClientKeyFilePath)){
            LOGGER.info("kmsClientKeyContent or kmsClientKeyFilePath is set up, using ClientKey to connect KMS.");
            this.kmsEncryptor = new ClientKeyKmsEncryptor(properties);
        }else{
            LOGGER.info("kmsClientKeyContent and kmsClientKeyFilePath are not set up, using Ram to connect KMS.");
            this.kmsEncryptor = new RamKmsEncryptor(properties);
        }
    }
    

    @Override
    public void doFilter(IConfigRequest request, IConfigResponse response, IConfigFilterChain filterChain)
            throws NacosException {
        String dataId = null;
        String group = null;
        try {
            if (request != null) {
                dataId = (String) request.getParameter(DATA_ID);
                group = (String) request.getParameter(GROUP);
                if (dataId.startsWith(CIPHER_PREFIX)) {
                    if (!StringUtils.isBlank((String)request.getParameter(CONTENT))) {
                        request.putParameter(CONTENT, kmsEncryptor.encrypt(request));
                    }
                }

                filterChain.doFilter(request, response);
            }
            if (response != null) {
                dataId = (String) response.getParameter(DATA_ID);
                group = (String) response.getParameter(GROUP);
                if (dataId.startsWith(CIPHER_PREFIX)) {
                    if (!StringUtils.isBlank((String)response.getParameter(CONTENT))) {
                        response.putParameter(CONTENT, kmsEncryptor.decrypt(response));
                    }
                }
            }
        } catch (ClientException e) {
            String message = String.format("KMS message:[%s], error message:[%s], dataId: %s, groupId: %s", e.getMessage(), e.getErrMsg(), dataId, group);
            throw new NacosException(NacosException.HTTP_CLIENT_ERROR_CODE, AliyunConst.formatHelpMessage(message), e);
        } catch (Exception e) {
            throw new NacosException(NacosException.INVALID_PARAM, AliyunConst.formatHelpMessage(e.getMessage()), e);
        }
    }
    
    @Override
    public int getOrder() {
        return 1;
    }

    @Override
    public String getFilterName() {
        return this.getClass().getName();
    }
    
    public void close() throws IOException {
        this.kmsEncryptor.close();
    }
}
