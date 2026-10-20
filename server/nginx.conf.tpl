# Security VPN: HTTPS API (шаблон, значения подставляет install.sh)

limit_req_zone $binary_remote_addr zone=svpn_api:10m rate=5r/s;

server {
    listen __API_PORT__ ssl;
    listen [::]:__API_PORT__ ssl;
    server_name _;

    ssl_certificate     /etc/securityvpn/tls/cert.pem;
    ssl_certificate_key /etc/securityvpn/tls/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    server_tokens off;
    client_max_body_size 8k;

    add_header X-Content-Type-Options nosniff always;
    add_header Cache-Control "no-store" always;

    root __APP_DIR__/api/public;

    location / {
        limit_req zone=svpn_api burst=20 nodelay;

        include fastcgi_params;
        fastcgi_pass unix:__PHP_SOCK__;
        fastcgi_param SCRIPT_FILENAME $document_root/index.php;
        fastcgi_param SCRIPT_NAME /index.php;
    }
}
