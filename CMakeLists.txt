cmake_minimum_required(VERSION 3.20.0)

if(BOARD STREQUAL "nrf7002dk/nrf5340/cpuapp")
  set(DTC_OVERLAY_FILE "${CMAKE_CURRENT_SOURCE_DIR}/nrf7002dk_nrf5340_cpuapp.overlay")
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(Nordic_OTA)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/main.c src/mac_auth.c)
target_sources(app PRIVATE
    src/tls_common.c
    src/wifi_net.c
    src/ntp_sync.c
    src/ota_manifest.c
    src/ota_download.c
    src/sensor_iface.c
)
