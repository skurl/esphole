idf_component_register(
    SRCS "main.c" "wifi.c" "blocklist.c" "dns_server.c" "stats.c" "http_server.c" "overrides.c"
    INCLUDE_DIRS "."
    EMBED_FILES "dashboard.html" "provision.html"
    REQUIRES esp_wifi esp_netif nvs_flash esp_partition lwip esp_timer esp_http_server)

# A fresh clone has no secrets.h (it is gitignored). Seed it from the example so
# the project builds; provisioning over the setup AP then fills in the rest.
if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/secrets.h")
    configure_file("${CMAKE_CURRENT_LIST_DIR}/secrets.h.example"
                   "${CMAKE_CURRENT_LIST_DIR}/secrets.h" COPYONLY)
endif()
