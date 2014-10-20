/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import java.util.HashSet;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;

import com.redhat.victims.util.Mode;
import com.redhat.victims.util.VictimsConfig;
import org.sonatype.nexus.proxy.IllegalOperationException;
import org.sonatype.nexus.proxy.ItemNotFoundException;
import org.sonatype.nexus.proxy.ResourceStoreRequest;
import org.sonatype.nexus.proxy.access.Action;
import org.sonatype.nexus.proxy.item.StorageFileItem;
import org.sonatype.nexus.proxy.item.StorageItem;
import org.sonatype.nexus.proxy.repository.ProxyRepository;
import org.sonatype.nexus.proxy.repository.Repository;
import org.sonatype.nexus.proxy.repository.RequestStrategy;
import org.sonatype.sisu.goodies.common.ComponentSupport;
import org.sonatype.sisu.goodies.eventbus.EventBus;


import com.google.common.base.Preconditions;

@Named(VictimsNexusScannerProcessor.NAME)
public class VictimsNexusScannerProcessor
		extends ComponentSupport
		implements RequestStrategy {

	public static final String NAME = "vulnerability-scanner";

	private static final Mode FINGERPRINT_MODE = Mode.valueOf(VictimsConfig.getProperty("victims.fingerprint"));
	private static final Mode METADATA_MODE = Mode.valueOf(VictimsConfig.getProperty("victims.metadata"));


	private static final String ERR_FINGERPRINT_MSG = VictimsConfig.getProperty("victims.fingerprint.err");
	private static final String ERR_METADATA_MSG = VictimsConfig.getProperty("victims.metadata.err");

	private final EventBus eventBus;
	private final List<VictimsNexusScanner> scanners;


	@Inject
	public VictimsNexusScannerProcessor(final EventBus eventBus,
	                                    final List<VictimsNexusScanner> scanners) {

		VictimsConfig.configureVictimsOptions();

		this.eventBus = Preconditions.checkNotNull(eventBus);
		this.scanners = Preconditions.checkNotNull(scanners);


		for (VictimsNexusScanner scanner : scanners) {
			log.debug("Scanner: {}", scanner);
		}

	}

	HashSet<String> getFingerprintVulnerabilities(final StorageFileItem item) {
		log.debug("Scanning item for vulnerabilities: {}", item.getPath());

		HashSet<String> cves = new HashSet<String>();

		for (VictimsNexusScanner scanner : scanners) {
			if (!(cves = scanner.getFingerprintVulnerabilities(item)).isEmpty()) {
				eventBus.post(new VulnerableItemFoundEvent(item.getRepositoryItemUid().getRepository(), item));
			}
		}

		return cves;
	}

	HashSet<String> getMetadataVulnerabilities(final StorageFileItem item) {
		log.debug("Scanning item for vulnerabilities: {}", item.getPath());

		HashSet<String> cves = new HashSet<String>();

		for (VictimsNexusScanner scanner : scanners) {
			if (!(cves = scanner.getMetadataVulnerabilities(item)).isEmpty()) {
				eventBus.post(new VulnerableItemFoundEvent(item.getRepositoryItemUid().getRepository(), item));
			}
		}

		return cves;
	}

	@Override
	public void onServing(final Repository repository, final ResourceStoreRequest resourceStoreRequest,
	                      final StorageItem storageItem)
			throws ItemNotFoundException, IllegalOperationException {
		if (storageItem instanceof StorageFileItem) {
			StorageFileItem file = (StorageFileItem) storageItem;

			HashSet<String> cves;

			//check file via fingerprint
			if (!FINGERPRINT_MODE.equals(Mode.disabled) && !(cves = getFingerprintVulnerabilities(file)).isEmpty()) {

				String errorMsg = createErrorMsg(storageItem, ERR_FINGERPRINT_MSG, cves);
				if (FINGERPRINT_MODE.equals(Mode.warning)) {
					log.warn(errorMsg);
				} else {
					log.error(errorMsg);
					throw new IllegalStateException(errorMsg);
				}
			}

			//check file via metadata
			if (!METADATA_MODE.equals(Mode.disabled) && !(cves = getMetadataVulnerabilities(file)).isEmpty()) {

				String errorMsg = createErrorMsg(storageItem, ERR_METADATA_MSG, cves);
				if (METADATA_MODE.equals(Mode.warning)) {
					log.warn(errorMsg);
				} else {
					log.error(errorMsg);
					throw new IllegalStateException(errorMsg);
				}
			}


		}
	}

	@Override
	public void onRemoteAccess(final ProxyRepository proxyRepository, final ResourceStoreRequest resourceStoreRequest,
	                           final StorageItem storageItem)
			throws ItemNotFoundException, IllegalOperationException {

	}

	@Override
	public void onHandle(final Repository repository, final ResourceStoreRequest resourceStoreRequest,
	                     final Action action)
			throws ItemNotFoundException, IllegalOperationException {

	}

	/**
	 * create and return error message
	 */
	private String createErrorMsg(StorageItem storageItem, String errMsg, HashSet<String> cves) {
		return NAME + " : " + storageItem.getName() + " " + errMsg + " " + cves.toString();
	}
}
