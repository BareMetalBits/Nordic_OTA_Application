/*
 * sensor_iface.c — I2C sensor polling thread.
 *
 * Polls every sensor in the table below on a fixed interval and logs each
 * channel via LOG_INF. Replaces the old LED-blink heartbeat thread.
 *
 * Both TMP117 and BMP280 run simultaneously (both physically wired to the
 * same I2C bus, different addresses) — see the devicetree overlay for the
 * node definitions this file references by label.
 */

#include "sensor_iface.h"

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(sensor_iface, LOG_LEVEL_INF);

/* ── Polling cadence ──────────────────────────────────────────────────────── */
#define SENSOR_POLL_INTERVAL_MS   2000

#define SENSOR_THREAD_STACK_SIZE  1536
#define SENSOR_THREAD_PRIORITY    7

/*
 * ════════════════════════════════════════════════════════════════════════
 * SENSOR REGISTRY — the one place to touch when adding a new I2C sensor.
 *
 * Every sensor here is read through the exact same generic Zephyr sensor
 * API call sequence (sensor_sample_fetch → sensor_channel_get per channel)
 * in sensor_poll_one() below. That function never changes when you add a
 * sensor — only this table grows.
 *
 * To add a new I2C sensor (e.g. an SHT3xD humidity sensor):
 *   1. Devicetree: add a node in the .overlay file (copy the tmp117 or
 *      bmp280 block as a template — new node label, "compatible" string,
 *      and I2C address for your part).
 *   2. Kconfig: enable that driver's CONFIG_xxx symbol in prj.conf.
 *   3. Here: define a `static const struct sensor_channel_spec` array
 *      listing which channels you want logged (see tmp117_channels /
 *      bmp280_channels below for the pattern), then add one entry to
 *      sensors[] referencing DEVICE_DT_GET(DT_NODELABEL(your_node_label)).
 * That's it — no changes to sensor_poll_one(), sensor_thread_fn(), or
 * sensor_iface_start().
 * ════════════════════════════════════════════════════════════════════════
 */

struct sensor_channel_spec {
	enum sensor_channel chan;   /* Zephyr channel enum, e.g. SENSOR_CHAN_AMBIENT_TEMP */
	const char          *label; /* Printed in the log line */
	const char          *unit;  /* Printed in the log line */
};

struct sensor_entry {
	const char                       *name;
	const struct device              *dev;
	const struct sensor_channel_spec *channels;
	size_t                            num_channels;
};

/* ── TMP117: temperature only ─────────────────────────────────────────────── */
static const struct sensor_channel_spec tmp117_channels[] = {
	{ SENSOR_CHAN_AMBIENT_TEMP, "Temp", "C" },
};

/* ── BMP280: temperature + pressure (no humidity channel on this part) ─────── */
static const struct sensor_channel_spec bmp280_channels[] = {
	{ SENSOR_CHAN_AMBIENT_TEMP, "Temp",     "C"   },
	{ SENSOR_CHAN_PRESS,        "Pressure", "kPa" },
};

static const struct sensor_entry sensors[] = {
	{
		.name         = "TMP117",
		.dev          = DEVICE_DT_GET(DT_NODELABEL(tmp117)),
		.channels     = tmp117_channels,
		.num_channels = ARRAY_SIZE(tmp117_channels),
	},
	{
		.name         = "BMP280",
		.dev          = DEVICE_DT_GET(DT_NODELABEL(bmp280)),
		.channels     = bmp280_channels,
		.num_channels = ARRAY_SIZE(bmp280_channels),
	},
	/* ── Add new sensors below this line ──────────────────────────────── */
};

#define NUM_SENSORS  ARRAY_SIZE(sensors)

/* ═══════════════════════════════════════════════════════════════════════════
 * sensor_poll_one() — generic fetch + log for any sensor in the table.
 *
 * Never needs editing when a new sensor is added — it only depends on the
 * generic struct device handle and the per-sensor channel list, both of
 * which come from the table above.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void sensor_poll_one(const struct sensor_entry *s)
{
	if (!device_is_ready(s->dev)) {
		LOG_WRN("%s: device not ready — check wiring/devicetree address", s->name);
		return;
	}

	int ret = sensor_sample_fetch(s->dev);
	if (ret != 0) {
		LOG_WRN("%s: sample fetch failed (%d)", s->name, ret);
		return;
	}

	for (size_t i = 0; i < s->num_channels; i++) {
		struct sensor_value val;

		ret = sensor_channel_get(s->dev, s->channels[i].chan, &val);
		if (ret != 0) {
			LOG_WRN("%s: %s channel read failed (%d)",
				s->name, s->channels[i].label, ret);
			continue;
		}

		/* struct sensor_value is a fixed-point val1.val2 pair (val2 in
		 * millionths) — sensor_value_to_double() would need floating
		 * point linked in, so format the fixed-point fields directly. */
		LOG_INF("%-7s %-9s = %d.%06d %s",
			s->name, s->channels[i].label,
			val.val1, val.val2 < 0 ? -val.val2 : val.val2,
			s->channels[i].unit);
	}
}

static void sensor_thread_fn(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	while (true) {
		for (size_t i = 0; i < NUM_SENSORS; i++) {
			sensor_poll_one(&sensors[i]);
		}
		k_msleep(SENSOR_POLL_INTERVAL_MS);
	}
}

K_THREAD_STACK_DEFINE(sensor_thread_stack, SENSOR_THREAD_STACK_SIZE);
static struct k_thread sensor_thread_data;

void sensor_iface_start(void)
{
	k_thread_create(&sensor_thread_data,
			sensor_thread_stack,
			K_THREAD_STACK_SIZEOF(sensor_thread_stack),
			sensor_thread_fn,
			NULL, NULL, NULL,
			SENSOR_THREAD_PRIORITY,
			0,
			K_NO_WAIT);
}
