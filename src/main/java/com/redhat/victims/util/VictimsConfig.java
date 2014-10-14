/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.util;

import java.util.ResourceBundle;

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


}
