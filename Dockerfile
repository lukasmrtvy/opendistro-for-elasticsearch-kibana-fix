FROM amazon/opendistro-for-elasticsearch-kibana:1.10.1

COPY routes.js /usr/share/kibana/plugins/opendistro_security/server/auth/types/openid/routes.js
