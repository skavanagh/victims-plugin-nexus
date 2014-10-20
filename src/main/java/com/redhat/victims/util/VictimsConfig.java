/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.util;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import org.apache.commons.lang.StringUtils;

public class VictimsConfig {

	private static ResourceBundle props = ResourceBundle.getBundle("VictimsConfig");

	/**
	 * returns attributes from victims configuration
	 *
	 * @param name property name
	 * @return property value
	 */
	public static String getProperty(String name) {
		return props.getString(name);
	}

	/**
	 * return all victim configuration properties
	 *
	 * @return property map
	 */
	public static Map<String, String> getProperties() {
		Map<String, String> propMap = new HashMap<String, String>();

		Enumeration<String> keys = props.getKeys();
		while (keys.hasMoreElements()) {
			String key = keys.nextElement();
			propMap.put(key, props.getString(key));
		}

		return propMap;
	}


	/**
	 * Set configuration options for victims-lib
	 *
	 * @link https://github.com/victims/victims-lib-java#configuration-options
	 */
	public static void configureVictimsOptions() {

		Map<String, String> config = VictimsConfig.getProperties();

		for (String key : config.keySet()) {
			//only set from properties if no JVM option
			if (StringUtils.isBlank(System.getProperty(key)) && StringUtils.isNotBlank(config.get(key))) {
				System.setProperty(key, config.get(key));
			}
		}

	}


}
