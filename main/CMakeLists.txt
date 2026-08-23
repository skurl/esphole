idf_component_register(
    SRCS "main.c" "wifi.c" "blocklist.c" "dns_server.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_netif nvs_flash esp_partition lwip esp_timer)
