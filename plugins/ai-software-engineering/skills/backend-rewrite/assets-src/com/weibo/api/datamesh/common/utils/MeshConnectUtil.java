package com.weibo.api.datamesh.common.utils;

import cn.sina.api.commons.util.ApiLogger;
import com.weibo.api.datamesh.common.constant.MeshConstant;
import com.weibo.api.datamesh.common.enums.ResourceTypeEnum;
import jnr.unixsocket.UnixSocketAddress;
import org.apache.commons.lang.StringUtils;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

public class MeshConnectUtil {

    private static final String MESH_CONNECT_HOST_ENV = "MESH_CONNECT_HOST";

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
        String meshConnectHost = System.getenv(MESH_CONNECT_HOST_ENV);
        if (StringUtils.isNotBlank(meshConnectHost)) {
            meshConnectHost = meshConnectHost.trim();
            isUnixDomainSocketOpen = false;
        } else {
            meshConnectHost = MeshConstant.LOCALHOST;
        }

        SocketAddress socketAddress = null;
        try {
            //获取端口
            if (isUnixDomainSocketOpen) {
                String unixSocketId = MeshConstant.UNIX_SOCKET_FILE_PREFIX + "_" + namespace;

                //创建socket文件
                SocketFileUtil.initSockFile(registry, group, namespace, topic, resourceTypeEnum, true);

                String sockFile = MeshConstant.SOCKET_FILE_PATH + "/" + unixSocketId + ".sock";


                //等待unix监听
                SocketFileUtil.tryConnectUnixSocket(sockFile);

                //初始化pool
                socketAddress = new UnixSocketAddress(sockFile);
            } else {
                //创建socket文件
                String socketPort = SocketFileUtil.initSockFile(registry, group, namespace, topic, resourceTypeEnum, false);

                //等待端口监听
                SocketFileUtil.tryConnectTcpSocket(meshConnectHost, socketPort);

                socketAddress = new InetSocketAddress(meshConnectHost, Integer.parseInt(socketPort));
            }
            return socketAddress;
        }
        catch (Exception e) {
            throw e;
        }
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
                int size = Integer.parseInt(evnMaxConnSize);
                if (size >= 1 && size <= 2048) {
                    maxConnSize = size;
                }
            } catch (Exception e) {
                ApiLogger.error("mesh evnMaxConnSize:" + evnMaxConnSize + " ,resource:" + resource, e);
            }
        }
        return maxConnSize;
    }
}
