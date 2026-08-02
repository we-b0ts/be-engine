package com.weibo.api.datamesh.common.utils;

import cn.sina.api.commons.util.ApiLogger;
import com.weibo.api.datamesh.common.constant.MeshConstant;
import com.weibo.api.datamesh.common.enums.ResourceTypeEnum;
import com.weibo.platform.commons.conf.ConfigLoaderFactory;
import jnr.unixsocket.UnixSocketAddress;
import org.apache.commons.lang.StringUtils;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

public class MeshConnectUtil {

    private static final String MESH_CONNECT_HOST_ENV = "MESH_CONNECT_HOST";
    private static final String MESH_CONNECT_HOST_CONFIG = "mesh.connect.host";

    public static SocketAddress getMeshConnectAddress(ResourceTypeEnum resourceTypeEnum, String registry, String group, String namespace) throws Exception {
        return getMeshConnectAddress(resourceTypeEnum, registry, group, namespace, null);
    }

    public static SocketAddress getMeshConnectAddress(ResourceTypeEnum resourceTypeEnum, String registry, String group, String namespace, String topic) throws Exception {
        boolean isUnixDomainSocketOpen = MeshConstant.UNIX_DOMAIN_SOCKET_DEFAULT_OPEN;
        String unixDomainSocketConfig = null;
        try {
            unixDomainSocketConfig = MeshVintageConfigUtil.getConfig(namespace, MeshConstant.UNIX_DOMAIN_SOCKET_ENABLE_CONFIG_NAME);
            if (unixDomainSocketConfig != null && !unixDomainSocketConfig.isEmpty()) {
                isUnixDomainSocketOpen = Boolean.parseBoolean(unixDomainSocketConfig);
            }
        }
        catch (Exception e) {
            ApiLogger.warn("mesh get config from vintage error, config key = " + MeshConstant.UNIX_DOMAIN_SOCKET_ENABLE_CONFIG_NAME + ", value = " + unixDomainSocketConfig, e);
        }

        SocketAddress socketAddress = null;
        try {
            if (isUnixDomainSocketOpen) {
                String unixSocketId = MeshConstant.UNIX_SOCKET_FILE_PREFIX + "_" + namespace;
                SocketFileUtil.initSockFile(registry, group, namespace, topic, resourceTypeEnum, true);
                String sockFile = MeshConstant.SOCKET_FILE_PATH + "/" + unixSocketId + ".sock";
                SocketFileUtil.tryConnectUnixSocket(sockFile);
                socketAddress = new UnixSocketAddress(sockFile);
            } else {
                String socketPort = SocketFileUtil.initSockFile(registry, group, namespace, topic, resourceTypeEnum, false);
                String meshConnectHost = getMeshConnectHost();
                SocketFileUtil.tryConnectTcpSocket(meshConnectHost, socketPort);
                socketAddress = new InetSocketAddress(meshConnectHost, Integer.parseInt(socketPort));
            }
            return socketAddress;
        }
        catch (Exception e) {
            throw e;
        }
    }

    static String getMeshConnectHost() {
        String environmentHost = System.getenv(MESH_CONNECT_HOST_ENV);
        if (StringUtils.isNotBlank(environmentHost)) {
            return environmentHost.trim();
        }

        try {
            String configuredHost = ConfigLoaderFactory.getConfigLoader().getProperty(MESH_CONNECT_HOST_CONFIG);
            if (StringUtils.isNotBlank(configuredHost)) {
                return configuredHost.trim();
            }
        } catch (Exception e) {
            ApiLogger.warn("mesh get connect host config error, config key = " + MESH_CONNECT_HOST_CONFIG, e);
        }

        return MeshConstant.LOCALHOST;
    }

    public static int getMaxConnSize(String resource){
        int maxConnSize = 1;
        String evnMaxConnSize = "";
        if (resource.equals("redis")) {
            maxConnSize = MeshConstant.REDIS_MAX_CONN_SIZE_DEFAULT;
            evnMaxConnSize = System.getenv("MESH_REDIS_MAX_CONN_SIZE");
        }
        if (resource.equals("mc")) {
            maxConnSize = MeshConstant.MC_MAX_CONN_SIZE_DEFAULT;
            evnMaxConnSize = System.getenv("MESH_MC_MAX_CONN_SIZE");
        }
        if (resource.equals("kv")) {
            maxConnSize = MeshConstant.KV_MAX_CONN_SIZE_DEFAULT;
            evnMaxConnSize = System.getenv("MESH_KV_MAX_CONN_SIZE");
        }
        if (resource.equals("uuid")) {
            maxConnSize = MeshConstant.UUID_MAX_CONN_SIZE_DEFAULT;
            evnMaxConnSize = System.getenv("MESH_UUID_MAX_CONN_SIZE");
        }
        if (resource.equals("vector")) {
            maxConnSize = MeshConstant.VECTOR_MAX_CONN_SIZE_DEFAULT;
            evnMaxConnSize = System.getenv("MESH_VECTOR_MAX_CONN_SIZE");
        }
        if (resource.equals("mcq")) {
            maxConnSize = MeshConstant.MCQ_MAX_CONN_SIZE_DEFAULT;
            evnMaxConnSize = System.getenv("MESH_MCQ_MAX_CONN_SIZE");
        }
        if (StringUtils.isNotEmpty(evnMaxConnSize)) {
            ApiLogger.info("mesh evnMaxConnSize:" + evnMaxConnSize + " ,resource:" + resource);
            try {
                int maxConnSizeFromEnvironment = Integer.parseInt(evnMaxConnSize);
                if (maxConnSizeFromEnvironment >= 1 && maxConnSizeFromEnvironment <= 2048) {
                    maxConnSize = maxConnSizeFromEnvironment;
                }
            } catch (Exception e) {
                ApiLogger.error("mesh evnMaxConnSize:" + evnMaxConnSize + " ,resource:" + resource, e);
            }
        }
        return maxConnSize;
    }
}
