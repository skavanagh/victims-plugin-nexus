/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.util;

/**
 * Enum to set modes for fingerprint and metadata rules
 */
public enum Mode {

    disabled("disabled"),
    warning("warning"),
    fatal("fatal");

    private final String value;

    private Mode(final String m) {
        value = m;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return this.getValue();
    }
}
