/**
 * Copyright 2014 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 * 
 * This code is distributed under the terms of the GNU Affero General
 * Public License (see <http://www.gnu.org/licenses/agpl.html>).
 */
package com.redhat.victims.nexus;

import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.inject.Named;

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
	
	private static ResourceBundle props = ResourceBundle.getBundle("VictimsConfig");
	private static final String VICTIMS_FINGERPRINT = props.getString("victims.fingerprint");
	private static final String VICTIMS_METADATA = props.getString("victims.metadata");
	private static final String ERR_FINGERPRINT_MSG = props.getString("victims.fingerprint.err");
	private static final String ERR_METADATA_MSG = props.getString("victims.metadata.err");
	
	private final EventBus eventBus;
	private final List<VictimsNexusScanner> scanners;


	@Inject
	public VictimsNexusScannerProcessor(final EventBus eventBus,
	                                    final List<VictimsNexusScanner> scanners) {


		this.eventBus = Preconditions.checkNotNull(eventBus);
		this.scanners = Preconditions.checkNotNull(scanners);


		for (VictimsNexusScanner scanner : scanners) {
			log.debug("Scanner: {}", scanner);
		}

	}

	boolean isVulnerableMetadata(final StorageFileItem item) {
		log.debug("Scanning item for vulnerabilities: {}", item.getPath());

		boolean vulnerable = false;
		for (VictimsNexusScanner scanner : scanners) {
			if (scanner.isVulnerableMetadata(item)) {
				vulnerable = true;
				eventBus.post(new VulnerableItemFoundEvent(item.getRepositoryItemUid().getRepository(), item));
			}
		}

		return vulnerable;
	}


	boolean isVulnerableFingerprint(final StorageFileItem item) {
		log.debug("Scanning item for vulnerabilities: {}", item.getPath());

		boolean vulnerable = false;
		for (VictimsNexusScanner scanner : scanners) {
			if (scanner.isVulnerableFingerprint(item)) {
				vulnerable = true;
				eventBus.post(new VulnerableItemFoundEvent(item.getRepositoryItemUid().getRepository(), item));
			}
		}

		return vulnerable;
	}

	@Override
	public void onServing(final Repository repository, final ResourceStoreRequest resourceStoreRequest,
	                      final StorageItem storageItem)
			throws ItemNotFoundException, IllegalOperationException {
		if (storageItem instanceof StorageFileItem) {
			StorageFileItem file = (StorageFileItem) storageItem;

			//check file via fingerprint
			if (!"disabled".equals(VICTIMS_FINGERPRINT) && isVulnerableFingerprint(file)) {

				if ("warning".equals(VICTIMS_FINGERPRINT)) {

					log.warn(NAME + " : " + storageItem.getName() + " - " + ERR_FINGERPRINT_MSG);

				} else {

					log.error(NAME + " : " + storageItem.getName() + " - " + ERR_FINGERPRINT_MSG);
					throw new IllegalStateException(NAME + " : " + storageItem.getName() + " - " + ERR_FINGERPRINT_MSG);

				}
			}
			//check file via metadata
			if (!"disabled".equals(VICTIMS_METADATA) && isVulnerableMetadata(file)) {

				if ("warning".equals(VICTIMS_METADATA)) {

					log.warn(NAME + " : " + storageItem.getName() + " - " + ERR_METADATA_MSG);

				} else {

					log.error(NAME + " : " + storageItem.getName() + " - " + ERR_METADATA_MSG);
					throw new IllegalStateException(NAME + " : " + storageItem.getName() + " - " + ERR_METADATA_MSG);

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
}
