idf_component_register(
    SRCS "main.c" "wifi.c" "blocklist.c" "dns_server.c" "stats.c" "http_server.c"
    INCLUDE_DIRS "."
    EMBED_FILES "dashboard.html"
    REQUIRES esp_wifi esp_netif nvs_flash esp_partition lwip esp_timer esp_http_server)
