# goagent-cf

使用 Cloudflare (或其他反向代理/CDN) 解决无可用 IP 的问题

## Usage

1. 在 GAE 上部署服务端 (参见原版文档)

2. 为服务端配置反向代理/CDN ([CDN Setup Guide](#cdn-setup-guide))

3. 新建 `local/proxy.user.ini` 并配置服务端的域名

    ```ini
    [gae]
    appid = instance1.yourdomain.com|instance2.yourdomain.com
    ```

    如果使用的反向代理是 Cloudflare, 可以加入以下配置
    
    ```ini
    [profile]
    .yourdomain.com = cloudflare
    ```

4. 运行 `local/proxy.py`

## Changes

基于 [v3.2.3](https://github.com/gaohuazuo/goagent-cf/tree/v3.2.3)

* 去掉了 runtime, 请自行安装依赖库

## Notes

* 这只是一份原型代码, 不会得到任何维护

* Cloudflare free plan 不支持三级域名, 如果提示 TLS handshake failure 可能是这个原因

* 原版 GoAgent 的其他功能可能受影响, 请勿使用

* 虽然不会被封 IP, 但公开域名可能被封

## How It Works

goagent

```
browser -> goagent client -> GAE (goagent server) -> website
```

goagent-cf

```
browser -> goagent client -> CDN -> GAE (goagent server) -> website
```

## CDN Setup Guide

1. 申请域名, [Freenom](http://www.freenom.com) 可以申请免费域名

2. 在 GAE 上设置使用自定义的域名, 具体方法请搜索 GAE custom domain

3. 配置 CDN, [Cloudflare](https://www.cloudflare.com) 提供免费 CDN
