# goagent-cf

使用 Cloudflare (或其他反向代理/CDN) 解决无可用 IP 的问题

# Usage

1. 在 GAE 上架设服务端 (参见原版文档)

2. 为服务端配置反向代理/CDN

3. 在 `local/proxy.ini` 中配置服务端的域名

    ```ini
    [gae]
    appid = instance1.example.com|instance2.example.com
    ```

4. 运行 `local/proxy.py`

# Changes

基于 v3.2.3

* 去掉了 runtime, 请自行安装依赖库

# Notes

* Cloudflare free plan 不支持三级域名

* 其他功能未经测试也不会维护, 请谨慎使用