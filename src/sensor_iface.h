#ifndef SENSOR_IFACE_H
#define SENSOR_IFACE_H

/*
 * sensor_iface.h — I2C sensor polling thread.
 *
 * Replaces led_status.{c,h}: same "start a background thread from main()"
 * shape, but instead of blinking an LED it periodically reads every sensor
 * in the sensors[] table in sensor_iface.c and logs the values (LOG_INF).
 *
 * Currently drives TMP117 (temperature) and BMP280 (temperature +
 * pressure) simultaneously. To add another I2C sensor, see the comment
 * block above sensors[] in sensor_iface.c — no change needed here.
 */

/**
 * @brief Start the periodic I2C sensor-polling thread.
 *
 * No preconditions beyond normal kernel init — unlike the old
 * led_status_start(), this does NOT depend on dk_leds_init() succeeding.
 */
void sensor_iface_start(void);

#endif /* SENSOR_IFACE_H */
