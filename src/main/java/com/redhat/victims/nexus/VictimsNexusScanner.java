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
	 * @return vulnerability indicator
	 */
	public boolean isVulnerableFingerprint(final StorageFileItem item) {

		boolean vulnerable = false;

		try {
			VictimsDBInterface db = getVictimsDB();

			try {
				db.synchronize();
			} catch (Exception ex) {
				log.error(ex.getMessage(), ex);
			}

			for (VictimsRecord vr : VictimsScanner.getRecords(item.getInputStream(), item.getName())) {
				HashSet<String> cves = db.getVulnerabilities(vr);
				//failed fingerprint check
				if (!cves.isEmpty()) {
					log.info("Failed FINGERPRINT " + item.getName());
					vulnerable = true;
				}
			}
		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);

		}
		return vulnerable;
	}

	/**
	 * check if storage file is vulnerable via meta data
	 *
	 * @param item storage item
	 * @return vulnerability indicator
	 */
	public boolean isVulnerableMetadata(final StorageFileItem item) {

		boolean vulnerable = false;

		try {
			VictimsDBInterface db = getVictimsDB();
			for (VictimsRecord vr : VictimsScanner.getRecords(item.getInputStream(), item.getName())) {

				for (String key : vr.getMetaData().keySet()) {
					HashSet<String> cves = db.getVulnerabilities(vr.getMetaData().get(key));
					//failed metadata check
					if (!cves.isEmpty()) {
						log.info("Failed METADATA " + item.getName());
						vulnerable = true;
					}
				}
			}

		} catch (Exception ex) {
			log.error(ex.getMessage(), ex);

		}


		return vulnerable;

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

