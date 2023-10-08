FROM registry.cn-hangzhou.aliyuncs.com/helloworldyu/base-alpine:latest
RUN mkdir -p /root/.config/clash/
RUN mkdir -p /app
RUN  wget -O /root/.config/clash/Country.mmdb https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb
COPY ./config.yaml /root/.config/clash/config.yaml
COPY ./bin/clash-linux-amd64 /app/clash
RUN chmod +x /app/clash
CMD ["/app/clash"]