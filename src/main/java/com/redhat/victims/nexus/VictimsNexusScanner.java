/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import javax.inject.Named;
import javax.inject.Singleton;

import com.redhat.victims.VictimsRecord;
import com.redhat.victims.VictimsScanner;
import com.redhat.victims.database.VictimsDB;
import com.redhat.victims.database.VictimsDBInterface;
import org.sonatype.nexus.proxy.item.StorageFileItem;
import org.sonatype.sisu.goodies.common.ComponentSupport;

import java.util.HashSet;


@Named
@Singleton
public class VictimsNexusScanner
        extends ComponentSupport

{


    /**
     * check if storage file is vulnerable via fingerprint
     *
     * @param item storage item
     * @return list of CVEs
     */
    public HashSet<String> getFingerprintVulnerabilities(final StorageFileItem item) {

        HashSet<String> cves = new HashSet<String>();

        try {
            VictimsDBInterface db = getVictimsDB();
            for (VictimsRecord vr : VictimsScanner.getRecords(item.getInputStream(), item.getName())) {
                cves = db.getVulnerabilities(vr);
            }
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);

        }
        return cves;
    }

    /**
     * check if storage file is vulnerable via meta data
     *
     * @param item storage item
     * @return list of CVEs
     */
    public HashSet<String> getMetadataVulnerabilities(final StorageFileItem item) {

        HashSet<String> cves = new HashSet<String>();

        try {
            VictimsDBInterface db = getVictimsDB();
            for (VictimsRecord vr : VictimsScanner.getRecords(item.getInputStream(), item.getName())) {

                for (String key : vr.getMetaData().keySet()) {
                    HashSet<String> cveCheck = db.getVulnerabilities(vr.getMetaData().get(key));

                    if (!cveCheck.isEmpty()) {
                        cves.addAll(cveCheck);
                    }
                }
            }

        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);

        }
        return cves;

    }

    /**
     * sync and return victims db
     *
     * @return victims db
     */
    private VictimsDBInterface getVictimsDB() {
        VictimsDBInterface db = null;
        try {
            db = VictimsDB.db();
            db.synchronize();
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }
        return db;
    }

}

